#!/bin/bash
set -e

echo "🚀 Setup script for Linux"


echo "📦 Installing required packages: curl, build-essential, pkg-config, libssl-dev, gcc-mingw-w64"
sudo apt install -y curl build-essential pkg-config libssl-dev gcc-mingw-w64 cargo

# Instalar rustup si no está instalado
if ! command -v rustup &> /dev/null
then
    echo "🦀 Installing rustup and Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✔ rustup already installed"
fi

# Agregar el target de Windows para cross-compilación
echo "🎯 Adding Windows GNU target for cross compilation..."
rustup target add x86_64-pc-windows-gnu

# Instalar linker para Windows
echo "🔗 Checking for x86_64-w64-mingw32-gcc linker..."
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null
then
    echo "❌ mingw-w64 compiler not found. Installing..."
    sudo apt install -y mingw-w64
else
    echo "✔ mingw-w64 compiler already installed"
fi

echo "✅ Setup completed successfully!"
echo "Recuerda abrir una nueva terminal o ejecutar: source ~/.cargo/env"

