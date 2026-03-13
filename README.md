MPCP ( multi-port catch protocol)

Protocol Designed & founded by: PowerTea-2 

Lead Implementation/Co-Maintainer: 


Licensed under GNU AGPLv3

Download instructions: 


Fedora/RHEL/CentOS:
sudo dnf install libsodium-devel libzstd-devel

Debian/Ubuntu
sudo apt install libsodium-dev libzstd-dev

Arch
sudo pacman -S libsodium zstd

Suse
sudo zypper install libsodium-devel libzstd-devel

Brew
brew install libsodium zstd


Compile with: 
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -O2 \
    mpcp_fixed.c -o mpcp -lsodium -lzstd -lm -lpthread
