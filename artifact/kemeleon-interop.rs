// Cross-implementation test-vector tool for the Kemeleon reference (Rust)
// against the Go implementation in pqobfs-lyrebird.
//
//   cargo run --release --example interop -- gen N     > vectors.json
//   cargo run --release --example interop -- decode  < go_encodings.json
//
// "gen" emits, per line, a JSON object with the reference's Kemeleon encodings
// and the corresponding raw FIPS 203 bytes, for both the encapsulation key and
// the ciphertext.
//
// "decode" reads {"ek_kmln":hex,"ct_kmln":hex} lines produced by the Go
// implementation, decodes them with the reference, and emits the recovered
// raw FIPS bytes so the caller can check they match.

use kemeleon::{Encode, OKemCore, Transcode};
use kem::Encapsulate;
use ml_kem::EncodedSizeUser;
use std::io::BufRead;

type K = kemeleon::MlKem768;

// The KCiphertext Debug impl prints both representations as hex:
//   Ciphertext { fips: "..", kmln: ".." }
fn ct_parts(dbg: &str) -> (String, String) {
    let field = |name: &str| -> String {
        let key = format!("{name}: \"");
        let i = dbg.find(&key).expect("field") + key.len();
        let j = dbg[i..].find('"').expect("close") + i;
        dbg[i..j].to_string()
    };
    (field("fips"), field("kmln"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("gen");
    let mut rng = rand::thread_rng();

    if mode == "gen" {
        let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
        for _ in 0..n {
            let (_dk, ek) = K::generate(&mut rng);
            let ek_kmln = hex::encode(ek.as_bytes());
            let ek_fips = hex::encode(ek.as_fips().as_bytes());
            let (ct, _ss) = ek.encapsulate(&mut rng).expect("encapsulate");
            let (ct_fips, ct_kmln) = ct_parts(&format!("{ct:?}"));
            println!(
                "{{\"ek_kmln\":\"{ek_kmln}\",\"ek_fips\":\"{ek_fips}\",\"ct_kmln\":\"{ct_kmln}\",\"ct_fips\":\"{ct_fips}\"}}"
            );
        }
        return;
    }

    // decode mode: recover FIPS bytes from Go-produced Kemeleon encodings
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let get = |name: &str| -> Vec<u8> {
            let key = format!("\"{name}\":\"");
            let i = line.find(&key).expect("field") + key.len();
            let j = line[i..].find('"').expect("close") + i;
            hex::decode(&line[i..j]).expect("hex")
        };
        let ek_kmln = get("ek_kmln");
        let ct_kmln = get("ct_kmln");

        let ek = <K as OKemCore>::EncapsulationKey::try_from_bytes(&ek_kmln)
            .expect("reference failed to decode the Go encapsulation key");
        let ek_fips = hex::encode(ek.as_fips().as_bytes());

        let ct = <K as OKemCore>::Ciphertext::try_from_bytes(&ct_kmln)
            .expect("reference failed to decode the Go ciphertext");
        let (ct_fips, _) = ct_parts(&format!("{ct:?}"));

        println!("{{\"ek_fips\":\"{ek_fips}\",\"ct_fips\":\"{ct_fips}\"}}");
    }
}
