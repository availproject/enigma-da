#!/bin/bash
set -e

# Ensure data directory exists with proper permissions
echo "Setting up data directory..."
mkdir -p /app/data || true
chmod 777 /app/data || true

# Test if directory is writable
if ! touch /app/data/.write_test 2>/dev/null; then
    echo "ERROR: /app/data is not writable!"
    echo "Volume permissions:"
    ls -la /app/data
    exit 1
fi
rm -f /app/data/.write_test

echo "Data directory is writable, starting application..."
exec /app/enigma-da