# TMiner

TMiner is a high-performance, multi-threaded Proof-of-Work Bitcoin miner written from scratch in C (C17 standard). It features a standalone implementation of the SHA-256 and Double-SHA256 (hash256) cryptographic algorithms, a native Stratum V1 network client for live Bitcoin pool mining, and support for multi-core parallel mining using POSIX threads.

TMiner has zero external library dependencies (no OpenSSL or third-party JSON libraries required); it relies strictly on standard C and POSIX system APIs.

---

## Features

- **Standard SHA-256 Implementation (FIPS 180-4)**
  - Self-contained implementation of SHA-256 and Double-SHA256 (`sha256d`).
  - Bitwise primitive helpers (`rotr`, `ch`, `maj`, sigma functions).
  - Streaming interface (`init`, `update`, `final`) and one-shot execution helpers.
  - Endianness handling and hex conversion utilities.

- **Stratum V1 Network Client**
  - Native TCP socket client communicating over the Stratum V1 protocol.
  - Full handshake implementation: `mining.subscribe`, `mining.authorize`, `mining.set_difficulty`, and `mining.notify`.
  - Dynamic generation of coinbase transactions (`extranonce1` + `extranonce2`) and Merkle tree roots from pool jobs.
  - Submits valid shares and network blocks to the pool via `mining.submit`.

- **Multi-Threaded Mining Engine**
  - Multi-threaded nonce distribution using `pthread`.
  - Automatic detection of available CPU cores (`sysconf(_SC_NPROCESSORS_ONLN)`).
  - Lock-free thread synchronization and metrics collection via `stdatomic.h`.
  - Real-time terminal telemetry reporting elapsed time, accepted/rejected shares, and hashrate in MH/s.

- **Local and Demonstration Modes**
  - Target conversion from Bitcoin compact `nBits` format to 256-bit big-endian integer targets.
  - Historic Bitcoin block header mining (Bitcoin Genesis Block and Block #125552).
  - Custom string Proof-of-Work mining with adjustable difficulty (leading hex zeros).
  - Built-in CPU Double-SHA256 throughput benchmark.

---

## Project Structure

```
TMiner/
├── include/
│   ├── sha256.h        # SHA-256 definitions, constants, and function prototypes
│   ├── tminer.h        # Block header structures, target calculations, and mining engine
│   └── stratum.h       # Stratum V1 protocol client definitions
├── src/
│   ├── sha256.c        # SHA-256 algorithm and hex conversion routines
│   ├── tminer.c        # Proof-of-Work verification, CPU thread workers, benchmark
│   ├── stratum.c       # TCP client, Stratum protocol parser, job dispatcher
│   └── main.c          # CLI argument parser and entry point
├── tests/
│   └── test_sha256.c   # NIST test vectors and validation suite
├── Makefile            # Build configuration (-O3, -pthread, -std=c17)
└── README.md
```

---

## Requirements

- Linux or POSIX-compliant environment
- GCC (version 9 or later) or Clang
- Make
- Standard C library (glibc) with `pthread` support

No external cryptographic libraries (such as OpenSSL) are required.

---

## Compilation

Use `make` to compile the optimized binary:

```bash
# Build the TMiner binary
make

# Run the test suite against standard NIST test vectors
make test

# Remove build artifacts and binary
make clean
```

The build defaults to `-O3` optimization and `-pthread` flags.

---

## Usage

### 1. Live Bitcoin Pool Mining (Stratum V1)

Connect to any Stratum-compatible Bitcoin mining pool. Provide the pool host, port, and your Bitcoin payout address.

#### Solo CKPool (Solo Bitcoin Mining)
Solo CKPool operates as a solo mining coordinator. When your miner finds a valid Bitcoin network block, the full block reward (currently 3.125 BTC plus transaction fees) is credited directly to your payout address.

```bash
./TMiner --pool solo.ckpool.org --port 3333 --user <YOUR_BITCOIN_WALLET_ADDRESS>
```
*(An optional worker name can be appended if desired, e.g. `<YOUR_BITCOIN_WALLET_ADDRESS>.worker1`)*

#### Public-Pool
```bash
./TMiner --pool public-pool.io --port 21496 --user <YOUR_BITCOIN_WALLET_ADDRESS>
```

#### Specifying Mining Threads
By default, TMiner detects and uses all available CPU cores. You can override the thread count using the `-t` or `--threads` option:

```bash
./TMiner --pool solo.ckpool.org --port 3333 --user <YOUR_BITCOIN_WALLET_ADDRESS> -t 4
```

---

### 2. Standalone & Offline Mining Modes

#### Benchmark CPU Throughput
Measures your CPU's Double-SHA256 hashing capacity across all cores over a 3-second evaluation window:

```bash
./TMiner --benchmark
```

#### Mine Historic Bitcoin Genesis Block
Mines the Bitcoin Genesis block header (Block #0) against the original target:

```bash
./TMiner --genesis
```

To search starting from nonce 0 across the full 32-bit range:

```bash
./TMiner --genesis-full
```

#### Custom Payload / String Mining
Finds a nonce such that `sha256d("<string><nonce>")` begins with a specified number of hexadecimal zeros:

```bash
./TMiner --string "MyBlockHeader-" --diff 5
```

---

## Command Line Options

```
Options:
  -o, --pool <host>       Stratum mining pool hostname/IP (e.g. solo.ckpool.org)
  -p, --port <port>       Stratum mining pool port (default: 3333)
  -u, --user <wallet>     Bitcoin wallet address or worker name
  -w, --pass <pass>       Worker password (default: x)
  -s, --string <text>     Mine a custom string/payload
  -d, --diff <zeros>      Difficulty (number of leading hex zeros, default: 4)
  -g, --genesis           Mine Bitcoin Genesis block header (demo window)
  -G, --genesis-full      Mine Bitcoin Genesis block header starting from nonce 0
  -S, --sample            Mine Bitcoin Block #125552 header
  -t, --threads <n>       Number of CPU mining threads (default: CPU cores)
  -n, --start-nonce <n>   Starting nonce (default: 0)
  -m, --max-nonce <n>     Maximum nonce (default: UINT32_MAX)
  -b, --benchmark         Run CPU Double-SHA256 hashrate benchmark
  -h, --help              Show help message
```

---

## Technical Notes

- **Stratum Coinbase Construction:** When a `mining.notify` job arrives from the pool, TMiner concatenates `coinb1 + extranonce1 + extranonce2 + coinb2`, hashes it with Double-SHA256 to produce the root transaction hash, and computes the 32-byte Merkle root by traversing the provided `merkle_branch` array.
- **Header Endianness:** Stratum transmits the 32-byte `prevhash` as eight 32-bit big-endian words. TMiner byte-swaps each word into little-endian format to construct the standard 80-byte block header expected by the Bitcoin Proof-of-Work specification.
- **Target Evaluation:** For pool shares, the difficulty parameter sent by `mining.set_difficulty` is mapped to a 256-bit target: `Target = Target_1 / Difficulty`. Nonces meeting this condition are submitted as valid shares. If a hash simultaneously satisfies the network target derived from `nBits`, a valid Bitcoin block has been found.
