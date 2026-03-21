<div align="center">

<br>

# ☾ ⋆⋆ MPCP ⋆⋆ ☽
### 🌌 Multi-Port Catch Protocol 🌌

<sub><em>sealed in silence · shaped for precision · built to not leak</em></sub>

<br>

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-5a6cff.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)

<br>

═══════════════════════════════════════  
▣ ▣ ▣   F O U N D A T I O N   ▣ ▣ ▣  
═══════════════════════════════════════  

**Founding Architect** · PowerTea-2  
**Protocol Specification** · v0.5  

═══════════════════════════════════════  

</div>

## ✨ Overview

MPCP is a high-assurance UDP protocol engineered for:

- ✦ **Z-score timing windows** and real-time event correlation  
- ✦ **XChaCha20-Poly1305 + HKDF** key derivation from shared nonce + PSK  
- ✦ **Dynamic port-hopping** with ghost chunks for traffic blending  
- ✦ **Tripwire detection** using z-score and χ² loss-pattern analysis  
- ✦ **Zero-copy pipeline** with `SCHED_FIFO` timing thread  

> *Built for researchers who require something that simply **does not leak**.*

<br>

═══════════════════════════════════════  
▣ ▣ ▣   I N S T A L L A T I O N   ▣ ▣ ▣  
═══════════════════════════════════════  

<details>
<summary><b>✨ Nix (fully reproducible)</b></summary>

    nix-shell -p libsodium libzstd gcc gnumake --run "bash"

</details>

<details>
<summary><b>🐧 Debian / Ubuntu</b></summary>

    sudo apt install libsodium-dev libzstd-dev

</details>

<details>
<summary><b>🎩 Fedora / RHEL</b></summary>

    sudo dnf install libsodium-devel libzstd-devel

</details>

<details>
<summary><b>🏹 Arch Linux</b></summary>

    sudo pacman -S libsodium zstd

</details>

<details>
<summary><b>🍎 macOS</b></summary>

    brew install libsodium zstd

</details>

<br>

═══════════════════════════════════════  
▣ ▣ ▣   C O M P I L A T I O N   ▣ ▣ ▣  
═══════════════════════════════════════  

    gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 \
        mpcp_fixed.c -o mpcp -lsodium -lzstd -lm -lpthread

<br>

═══════════════════════════════════════  
▣ ▣ ▣   L E G A L   ▣ ▣ ▣  
═══════════════════════════════════════  

Licensed under the **GNU Affero General Public License v3.0**  

Moral Rights asserted by PowerTea-2 under EU copyright law  

Any derivative must:

- Clearly mark itself as a fork  
- Preserve the **Founding Architect** credit  
- Label deviations as **Unverified Implementation**  

See `NOTICE` and `LICENSE` for full terms.

<br>

═══════════════════════════════════════  
▣ ▣ ▣   D O C U M E N T A T I O N   ▣ ▣ ▣  
═══════════════════════════════════════  

- **Full Protocol Spec** — `MPCP_v0.5_FINAL_PowerTea-2.pdf`  
- **Legal Notice** — `NOTICE`  
- **Security Note** — research + educational use only  
- **Warranty** — none  

<br>

<div align="center">

═══════════════════════════════════════  
☾ carved under cold starlight ☽  
**PowerTea-2**  
═══════════════════════════════════════  

</div>
