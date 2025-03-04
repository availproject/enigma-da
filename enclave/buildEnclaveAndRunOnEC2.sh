#!/bin/bash
FILE=enclaveserver.eif
if [ -f "$FILE" ]; then
    rm $FILE
fi

RunningEnclave=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
if [ -n "$RunningEnclave" ]; then
	nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID");
fi

docker rmi -f $(docker images -a -q)
docker rmi enclaveserver:latest
pkill vsock-proxy

docker build --network=host -t enclaveserver:latest .
nitro-cli build-enclave --docker-uri enclaveserver:latest  --output-file enclaveserver.eif > EnclaveImage.log

vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 &
vsock-proxy 9001 refactored-palm-tree-97w79qxwxr63xjvw-3000.app.github.dev 443 --config vsock-proxy.yaml &

nitro-cli run-enclave --cpu-count 2 --memory 10024 --enclave-cid 16 --eif-path enclaveserver.eif  
