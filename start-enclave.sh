docker build ./ -t encryption-service
nitro-cli build-enclave --docker-uri encryption-service --output-file encryption-service.eif

ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
[ "$ENCLAVE_ID" != "null" ] && nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}
EIF_SIZE=$(du -b --block-size=1M "encryption-service.eif" | cut -f 1)
ENCLAVE_MEMORY_SIZE=$(((($EIF_SIZE * 4 + 1024 - 1)/1024) * 1024))
nitro-cli run-enclave --cpu-count 2 --memory $ENCLAVE_MEMORY_SIZE --eif-path encryption-service.eif --debug-mode

ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
[ "$ENCLAVE_ID" != "null" ] && nitro-cli console --enclave-id ${ENCLAVE_ID}