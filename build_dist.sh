#!/bin/bash
set -e

echo "=== Packaging MicroPKI Distribution for Ubuntu (Linux) ==="

# 1. Clean release directory
rm -rf release
mkdir -p release/micropki-dist

# 2. Build for Linux
echo "=> Compiling Go binary for linux/amd64..."
# Using CGO_ENABLED=1 might be required for go-sqlite3, but cross-compiling CGO from Windows to Linux requires a cross-compiler.
# We will use zig cc or just output a script to build it if CGO fails, 
# BUT wait: github.com/mattn/go-sqlite3 requires CGO. 
# Since compiling CGO across OS boundaries is notoriously hard without proper toolchains, 
# we'll build it if the user is already on Linux, OR we'll provide the source and let the installer build it on the target machine.
# Actually, providing the source and a simple "install.sh" that runs "go build" on the target machine is MUCH safer for CGO dependencies like sqlite3.

echo "=> Copying source code..."
cp -r cmd internal go.mod go.sum makefile release/micropki-dist/ 2>/dev/null || cp -r cmd internal go.mod makefile release/micropki-dist/

echo "=> Copying documentation and demo..."
cp demo.sh release/micropki-dist/
cp -r Docs_extra release/micropki-dist/

echo "=> Creating installation script for Ubuntu..."
cat << 'EOF' > release/micropki-dist/install.sh
#!/bin/bash
set -e

echo "=== MicroPKI Installer for Ubuntu ==="

echo "=> Checking dependencies..."
if ! command -v openssl &> /dev/null; then
    echo "Installing openssl..."
    sudo apt-get update && sudo apt-get install -y openssl
fi

if ! command -v go &> /dev/null; then
    echo "Installing Go (golang)..."
    sudo apt-get update && sudo apt-get install -y golang
fi

echo "=> Compiling MicroPKI..."
go mod tidy
go build -o micropki ./cmd/micropki

echo "=> Setting permissions..."
chmod +x micropki demo.sh

echo "=== Installation Complete! ==="
echo "You can now run the demonstration script:"
echo "./demo.sh"
EOF

chmod +x release/micropki-dist/install.sh

# 3. Create Tar Archive
echo "=> Creating tar.gz archive..."
cd release
tar -czvf micropki-ubuntu-dist.tar.gz micropki-dist
cd ..

echo "=> Done! Distribution package is ready at: release/micropki-ubuntu-dist.tar.gz"
