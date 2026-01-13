#!/usr/bin/env bash
set -e

# Ector uninstaller script

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="ector"

echo "Uninstalling ector..."

# Check if binary exists
if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
  rm "$INSTALL_DIR/$BINARY_NAME"
  echo "✓ Removed $INSTALL_DIR/$BINARY_NAME"
else
  echo "ℹ Binary not found at $INSTALL_DIR/$BINARY_NAME"
fi

# Check common alternative locations
COMMON_PATHS=(
  "/usr/local/bin/$BINARY_NAME"
  "$HOME/bin/$BINARY_NAME"
  "/opt/bin/$BINARY_NAME"
)

for path in "${COMMON_PATHS[@]}"; do
  if [ -f "$path" ]; then
    echo "Found ector at: $path"
    read -p "Remove this too? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      if [ -w "$path" ]; then
        rm "$path"
        echo "✓ Removed $path"
      else
        echo "Need sudo to remove $path"
        sudo rm "$path"
        echo "✓ Removed $path"
      fi
    fi
  fi
done

# Check if ector is still in PATH
if command -v ector &>/dev/null; then
  REMAINING_PATH=$(which ector)
  echo ""
  echo "⚠ ector still found at: $REMAINING_PATH"
  echo "You may want to remove it manually"
else
  echo ""
  echo "✓ ector successfully uninstalled"
fi
