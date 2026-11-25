# Raw ML-KEM-768 encapsulation keys from kyber-py (pure Python FIPS 203).
import sys
from kyber_py.ml_kem import ML_KEM_768
n = int(sys.argv[1]); out = sys.argv[2]
with open(out, "wb") as f:
    for _ in range(n):
        ek, dk = ML_KEM_768.keygen()
        assert len(ek) == 1184
        f.write(ek)
