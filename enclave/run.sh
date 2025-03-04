ip addr add 127.0.0.1/32 dev lo

ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1   refactored-palm-tree-97w79qxwxr63xjvw-3000.app.github.dev" >> /etc/hosts

#touch /app/libnsm.so

python3 /app/forwarder.py &
python3 /app/enclave_server.py