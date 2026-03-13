# 🚀 MPCP - Multi-Port Catch Protocol

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A sophisticated privacy-research protocol designed for multi-port communication and event correlation analysis.

---

## 📋 Overview

**MPCP** (Multi-Port Catch Protocol) is a cryptographically-secured protocol featuring:

- **Advanced Event Correlation**: Z-score normalization for timing-window analysis
- **Cryptographic Security**: Built with libsodium
- **Compression Support**: Integrated zstd compression
- **Multi-threaded Architecture**: Optimized for concurrent operations
- **Research-Grade**: Designed for privacy research and educational purposes

**Protocol Specification**: Version 0.5  
**Founding Architect**: PowerTea-2

---

## 📦 Installation

### Prerequisites

Choose the installation command for your operating system:

#### Fedora/RHEL/CentOS
```bash
sudo dnf install libsodium-devel libzstd-devel
```

#### Debian/Ubuntu
```bash
sudo apt install libsodium-dev libzstd-dev
```

#### Arch Linux

                                                –
                                              . O+  `
                                            ` OOO /
                                         ` +OOOO :
                                      ` +OOOOOO :
                                      - +OOOOOO+ :
                                  ` / : - : + +OOOO+ :
                                ` / ++++ / +++++++ :
                              ` / ++++++++++++++ :
                            ` / +++OOOOOOOOOOO/ `
                          . / OOOSSSSO++OSSSSSO+`
                        . OOSSSSSO - ` ` ` ` /OSSSSSS+ `
                    -  OSSSSSSO .                : SSSSSSSO .
                  : OSSSSSSS /                     OSSSSO+++ .
               / OSSSSSSSS /                     +SSSSOOO/ -  
         `  / OSSSSSO+ /  : -                     - : / +OSSSSO+ -
       ` +SSO+ : -  `                                             ` . - / +OSO :
    ` ++ :  .                                                                      `  - / + /
    .  `                                                                                      ` /

```bash
sudo pacman -S libsodium zstd
```

#### openSUSE
```bash
sudo zypper install libsodium-devel libzstd-devel
```

#### macOS (Homebrew)
```bash
brew install libsodium zstd
```

---

## 🔨 Compilation

Compile MPCP with the following command:

```bash
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 \ 
    mpcp_fixed.c -o mpcp -lsodium -lzstd -lm -lpthread
```

This will generate the `mpcp` executable with all required libraries linked.

---

## 📄 Licensing

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL v3).

See [LICENSE](LICENSE) file for full details.

---

## ⚖️ Legal & Attribution

### Moral Rights & Attribution

MPCP was designed and authored by **PowerTea-2**, the "Founding Architect."

The author asserts their Moral Right to be identified as the creator of this work under the copyright laws of the European Union, including the right of integrity.

### Key Requirements

✋ **No Misrepresentation**: Modified versions must be clearly marked as different from the original and labeled as derivatives of MPCP by PowerTea-2.

📢 **Attribution in User Interfaces**: Any derivative work must preserve the "Founding Architect" and "Protocol Specification" credits in all interactive user interfaces (CLI splash screens, --help menus, --version outputs).

🔒 **Architectural Integrity**: Modifications to core Z-score normalization or timing-window logic must be labeled as "Unverified Implementation." The name "MPCP" without qualification may only be used for implementations strictly adhering to PowerTea-2 Protocol Specification v0.5.

⚠️ **Disclaimer**: This protocol is provided for privacy-research and educational purposes "as-is" without warranty. PowerTea-2 does not endorse, encourage, or facilitate any illegal use. Users assume all legal and technical risks.

For complete legal terms, see [NOTICE](NOTICE) file.

---

## 📚 Documentation

- **Protocol Specification**: See `MPCP_v0.5_FINAL_PowerTea-2.pdf` for detailed technical specification
- **Legal Notice**: See `NOTICE` for full attribution and usage requirements

---

## 🔐 Security & Privacy

This protocol is designed for privacy research and educational purposes. Users are responsible for ensuring compliant and ethical use of this software.

---

## 📞 Support

For issues, questions, or contributions, please refer to the GitHub repository.

---

**Created with ❤️ by PowerTea-2**
