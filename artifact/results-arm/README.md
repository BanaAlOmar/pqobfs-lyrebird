# ARM (Apple Silicon) measurements

Collected on an Apple Silicon MacBook Pro, in an arm64 Linux VM
(4 vCPUs, Go 1.24.7 linux/arm64, CIRCL v1.5.0 -- which has no
arm64 assembly for ML-KEM, so the AVX issue of the x86 runs does not arise).

| file | contents |
|---|---|
| radix_bench.txt | codec benchmarks, 5 runs |
| before/, final/ | in-process primitives and handshake, original commit 9324cd3 vs this branch |
| final_1core/ | in-process handshake with GOMAXPROCS=1, pinned to one core |
| junk_cost.json | bridge CPU per junk connection and per honest handshake, per suite |
| conn_latency_rtt0.json | full-connection-path latency on loopback, 500 connections each |
| throughput_c*.json | bridge throughput at 2, 8, 32 concurrent clients |
| encap_timing.json | bridge encapsulate-and-encode time, rejection vs default encoding, 20,000 each |
