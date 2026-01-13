#!/usr/bin/env bash
set -e

# Ector installer script

REPO="silranucci/ector"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
Linux*)
  case "$ARCH" in
  x86_64) PLATFORM="linux-x86_64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
  esac
  ;;
Darwin*)
  case "$ARCH" in
  x86_64) PLATFORM="macos-x86_64" ;;
  arm64) PLATFORM="macos-aarch64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
  esac
  ;;
*)
  echo "Unsupported OS: $OS"
  exit 1
  ;;
esac

echo "Installing ector for $PLATFORM..."

mkdir -p "$INSTALL_DIR"

DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/ector-${PLATFORM}.tar.gz"
echo "Downloading from $DOWNLOAD_URL"

curl -L "$DOWNLOAD_URL" | tar xz -C "$INSTALL_DIR"

chmod +x "$INSTALL_DIR/ector"

echo ""
echo "✓ Ector installed to $INSTALL_DIR/ector"
echo ""

# Check if in PATH
if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
  echo "You can now run: ector --help"
else
  echo "Add to your PATH by adding this to your ~/.bashrc or ~/.zshrc:"
  echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
  echo ""
  echo "Or run directly: $INSTALL_DIR/ector --help"
fi
