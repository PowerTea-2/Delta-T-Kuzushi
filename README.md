<div align="center">

# ⚙ ClockWork ⚙
### ⋆⁺₊⋆ Gearbound synchronization for MPCP ⋆⁺₊⋆

<sub><em>crafted in starlight, wound by precision, and built to keep time</em></sub>

<br>

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-5a6cff.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)

<br>

⚙═════════════════════◈═════════════════════⚙  
⋆⋆⋆ P R O J E C T I D E N T I T Y ⋆⋆⋆  
⚙═════════════════════◈═════════════════════⚙

**Protocol** · MPCP  
**Project** · ClockWork  
**Maintainer** · PowerTea-2

⚙═════════════════════◈═════════════════════⚙

</div>

## ✨ Overview

ClockWork is the tooling and reference implementation built around **MPCP** — the **Multi-Port Catch Protocol**.

It is engineered for:

- **Z-score timing windows** and real-time event correlation
- **XChaCha20-Poly1305 + HKDF** key derivation from shared nonce + PSK
- **Dynamic port-hopping** with ghost chunks for traffic blending
- **Tripwire detection** using z-score and χ² loss-pattern analysis
- **Zero-copy pipeline** with `SCHED_FIFO` timing thread

> *A system wound tight enough to hold a signal, and quiet enough to keep it hidden.*

<br>

⚙═════════════════════◈═════════════════════⚙  
⋆⋆⋆ M P C P & C l o c k W o r k ⋆⋆⋆  
⚙═════════════════════◈═════════════════════⚙

**MPCP** is the protocol.  
**ClockWork** is the software built around it.

- MPCP defines the timing, transport, and cryptographic structure
- ClockWork provides the implementation and user-facing tooling

This keeps the protocol specification separate from the application that uses it.

<br>

⚙═════════════════════◈═════════════════════⚙  
⋆⋆⋆ I N S T A L L A T I O N ⋆⋆⋆  
⚙═════════════════════◈═════════════════════⚙

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

    sudo dnf install libsodium-devel libzstd-dev

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

⚙═════════════════════◈═════════════════════⚙  
⋆⋆⋆ B U I L D ⋆⋆⋆  
⚙═════════════════════◈═════════════════════⚙

    gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 \
        clockwork.c -o clockwork -lsodium -lzstd -lm -lpthread

If your source filename is different, adjust the first line accordingly.

<br>

⚙═════════════════════◈═════════════════════⚙  
⋆⋆⋆ L E G A L ⋆⋆⋆  
⚙═════════════════════◈═════════════════════⚙

Licensed under the **GNU Affero General Public License v3.0**.

**Moral Rights** asserted by PowerTea-2 under EU copyright law.

Any derivative must:

- clearly mark itself as a fork
- preserve the **Founding Architect** credit in all UI elements
- label deviations from the MPCP spec as **Unverified Implementation**

See `NOTICE` and `LICENSE` for full terms.

<br>

⚙═════════════════════◈═════════════════════⚙  
⋆⋆⋆ D O C U M E N T A T I O N ⋆⋆⋆  
⚙═════════════════════◈═════════════════════⚙

- **Full Protocol Spec** — `MPCP_v0.5_FINAL_PowerTea-2.pdf`
- **Legal Notice** — `NOTICE`
- **Security Note** — research + educational use only
- **Warranty** — none

<br>

<div align="center">

⚙═════════════════════◈═════════════════════⚙  
⋆⁺₊⋆ c a r v e d i n s t a r l i g h t ⋆⁺₊⋆  
⚙═════════════════════◈═════════════════════⚙

</div>
