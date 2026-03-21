# 🌌 MPCP — Multi-Port Catch Protocol

[<image-card alt="License: AGPL v3" src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" ></image-card>](https://www.gnu.org/licenses/agpl-3.0)

**v0.5** — A cryptographically sealed, multi-port catch protocol for privacy research and event-correlation analysis.
✧･ﾟ: ✧･ﾟ:   ⋆   :･ﾟ✧:･ﾟ✧
**Founding Architect** — PowerTea-2  
**Protocol Specification** — v0.5
✧･ﾟ: ✧･ﾟ:   ⋆   :･ﾟ✧:･ﾟ✧
text## ✨ Overview

MPCP is a high-assurance UDP protocol engineered for:

- Z-score timing windows and real-time event correlation  
- XChaCha20-Poly1305 + HKDF key material derived from shared nonce + PSK  
- Dynamic port-hopping with ghost chunks for traffic blending  
- Tripwire detection (z-score + χ² loss-pattern analysis)  
- Zero-copy pipeline with SCHED_FIFO timing thread  

Built for researchers who need something that simply **does not leak**.

## 🌠 Installation

### Nix (recommended — fully reproducible)

```bash
nix-shell -p libsodium libzstd gcc gnumake --run "bash"
Inside the shell, compile with:
Bashgcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 mpcp_fixed.c -o mpcp -lsodium -lzstd -lm -lpthread
Traditional package managers
Fedora / RHEL
Bashsudo dnf install libsodium-devel libzstd-devel
Debian / Ubuntu
Bashsudo apt install libsodium-dev libzstd-dev
Arch
Bashsudo pacman -S libsodium zstd
macOS
Bashbrew install libsodium zstd
text✧･ﾟ: *✧･ﾟ:*   ⋆   *:･ﾟ✧*:･ﾟ✧
⚡ Compilation
Bashgcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 \
    mpcp_fixed.c -o mpcp -lsodium -lzstd -lm -lpthread
📜 Legal & Moral Rights
Licensed under GNU Affero General Public License v3.0.
Moral Rights asserted by PowerTea-2 under EU copyright law.
Any derivative must:

Clearly mark itself as a fork
Preserve the “Founding Architect” credit in all UI elements
Label any deviation from v0.5 spec as “Unverified Implementation”

See NOTICE and LICENSE for full terms.
text✧･ﾟ: *✧･ﾟ:*   ⋆   *:･ﾟ✧*:･ﾟ✧
📖 Documentation

Full Protocol Spec — MPCP_v0.5_FINAL_PowerTea-2.pdf
Legal Notice — NOTICE

🔒 Security & Research Note
MPCP is provided strictly for privacy research and educational use.
No warranty. Use at your own risk.
text✧･ﾟ: *✧･ﾟ:*   ⋆   *:･ﾟ✧*:･ﾟ✧
Created under starlight by PowerTea-2
text---

**How to use it:**
1. Go to your GitHub repo  
2. Click “Edit README.md”  
3. Delete everything  
4. Paste the entire block above  
5. Commit

It will look beautiful in dark mode with glowing stars and curly fantasy dividers — exactly the sparkly night-sky aesthetic you asked for.

Want any last tweak (different star pattern, add a small ASCII constellation at the top, change one sentence)? Just say and I’ll update it instantly.  

Otherwise, paste it and enjoy your new cosmic README ✨🌌
