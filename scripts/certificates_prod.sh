#!/bin/bash
set -e

# Prompt for DNS names and IPs
echo "=== Certificate Generation for Production ==="
echo ""
echo "Enter DNS names for the server certificate (comma-separated):"
echo "Example: mydomain.com,api.mydomain.com,*.mydomain.com"
read -p "DNS names: " dns_input

echo ""
echo "Enter IP addresses for the server certificate (comma-separated):"
echo "Example: 192.168.1.100,10.0.0.50"
read -p "IP addresses: " ip_input

echo ""
read -p "Enter primary domain for CN (e.g., mydomain.com): " primary_domain

echo ""
read -p "Enter client identifier/name (e.g., avail-client): " client_name

echo ""
echo "Generating certificates..."
echo ""

mkdir -p certs_prod && cd certs_prod

# Generate CA
echo "1. Generating CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=CA"

# Generate server cert with SAN
echo "2. Generating server key and CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=${primary_domain}"

# Build SAN entries from user input
echo "3. Building SAN configuration..."
cat > server.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
EOF

# Add DNS entries
dns_counter=1
IFS=',' read -ra DNS_ARRAY <<< "$dns_input"
for dns in "${DNS_ARRAY[@]}"; do
    dns=$(echo "$dns" | xargs)  # trim whitespace
    if [ -n "$dns" ]; then
        echo "DNS.${dns_counter} = ${dns}" >> server.conf
        ((dns_counter++))
    fi
done

# Add IP entries
ip_counter=1
IFS=',' read -ra IP_ARRAY <<< "$ip_input"
for ip in "${IP_ARRAY[@]}"; do
    ip=$(echo "$ip" | xargs)  # trim whitespace
    if [ -n "$ip" ]; then
        echo "IP.${ip_counter} = ${ip}" >> server.conf
        ((ip_counter++))
    fi
done

echo "4. Signing server certificate..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extensions v3_req -extfile server.conf

# Generate client cert
echo "5. Generating client certificate..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=${client_name}"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

# Cleanup
echo "6. Cleaning up temporary files..."
rm server.csr client.csr server.conf

echo ""
echo "✅ Certificate generation complete!"
echo ""
echo "Generated files in ./certs/:"
echo "  - ca.crt, ca.key (CA certificate and key)"
echo "  - server.crt, server.key (Server certificate and key)"
echo "  - client.crt, client.key (Client certificate and key)"
echo ""
echo "Server certificate includes:"
echo "  CN: ${primary_domain}"
echo "  DNS: ${dns_input}"
echo "  IPs: ${ip_input}"
echo ""
echo "Client certificate CN: ${client_name}"

