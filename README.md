# Delta-T

**Delta-T** is a performance-focused, minimal, secure file transfer and relay engine, forked from ClockWork. Designed for reliability, atomic precision, and modern cryptography.

---

## Features

- **Zero-heap, ChaCha20/Ed25519 encryption**
- **Zstandard compression, decoy (ghost) chunk support**
- **Selective-repeat sliding window for loss tolerance**
- **Atomic, lock-free synchronization**
- **Tripwire anomaly detection and stealth mode**
- **No unnecessary dependencies – pure C, POSIX**

---

## Quick Build Guide

**Requirements:**  
- GCC (>= 9)
- `libsodium-dev` (for Ed25519/ChaCha20)
- `libzstd-dev` (for Zstandard compression)
- POSIX threads (`-lpthread`)

### 🟢 Ubuntu / Debian

```sh
sudo apt update
sudo apt install build-essential libsodium-dev libzstd-dev
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O3 Delta-T-Working-0.5 -o delta-t -lsodium -lzstd -lm -lpthread
```

### 🟦 Fedora

```sh
sudo dnf install gcc libsodium-devel libzstd-devel make
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O3 Delta-T-Working-0.5 -o delta-t -lsodium -lzstd -lm -lpthread
```

### 🐧 Arch Linux

```sh
sudo pacman -S base-devel libsodium zstd
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O3 Delta-T-Working-0.5 -o delta-t -lsodium -lzstd -lm -lpthread
```

### Manual Build (Any Distro)

1. Ensure you have GCC and libraries above.
2. Compile:

   ```sh
   gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O3 Delta-T-Working-0.5 -o delta-t -lsodium -lzstd -lm -lpthread
   ```

---

## What is Delta-T?

Delta-T is a minimal, atomic, and high-security transfer engine. It splits files into cryptographically secure chunks, compresses, and relays them with hardware-level precision for ultra-low latency and high reliability.

- **No dynamic memory usage for keystreams**
- **Timings: hardware nanosecond precision**
- **NAT-resilient, stealth-optional**

---

## Why "Delta-T"?

Reflects precise, minimal, and measurable data transmission intervals (Δt).

---

## License

[Your License Here]
