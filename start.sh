#!/bin/bash


echo "=== Environment Variables ==="
echo "SERVER_PORT: ${SERVER_PORT}"
echo "SERVER_HOST: ${SERVER_HOST}"
echo "RUST_LOG: ${RUST_LOG}"
echo "RUST_BACKTRACE: ${RUST_BACKTRACE}"

# Show if certificates are loaded from env (first 50 chars)
if [ -n "$CA_CERT" ]; then
    echo "CA_CERT: loaded (${#CA_CERT} chars)"
    echo "CA_CERT preview: ${CA_CERT:0:50}..."
else
    echo "CA_CERT: not set (will use ca.crt file)"
fi

if [ -n "$SERVER_CERT" ]; then
    echo "SERVER_CERT: loaded (${#SERVER_CERT} chars)"
    echo "SERVER_CERT preview: ${SERVER_CERT:0:50}..."
else
    echo "SERVER_CERT: not set (will use server.crt file)"
fi

if [ -n "$SERVER_KEY" ]; then
    echo "SERVER_KEY: loaded (${#SERVER_KEY} chars)"
    echo "SERVER_KEY preview: ${SERVER_KEY:0:50}..."
else
    echo "SERVER_KEY: not set (will use server.key file)"
fi

echo "==========================="
echo ""


/app/enigma-da