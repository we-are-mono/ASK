#!/bin/sh
# Install cross-compilation host dependencies for ASK on Debian trixie
set -e

echo "Enabling arm64 multiarch..."
sudo dpkg --add-architecture arm64
sudo apt update

echo "Installing cross-compilation toolchain and libraries..."
sudo apt install -y \
    crossbuild-essential-arm64 \
    libcli-dev:arm64 \
    libpcap-dev:arm64 \
    libmnl-dev:arm64 \
    libxml2-dev:arm64 \
    libtclap-dev \
    pkg-config

echo "Done. Run 'make' to build."
