# Verifying Quote

## TEE Resources Used

- [Dstack Attestation](https://github.com/Dstack-TEE/dstack/blob/master/attestation.md)
- [Dstack Examples (verify.py)](https://github.com/Dstack-TEE/dstack-examples/pull/16/files#diff-a37816fef898fbd92c747eefa6ed85ede031a8bcd3288295976c6772ffd69fcc)
- [Dstack Examples (report.json)](https://github.com/Dstack-TEE/dstack-examples/pull/16/files#diff-1cc8afd3984cca7f2e2f22b30c72c7b37a6cf2158fb968553bfab575a0cd64ff)

## TEE Libraries Used

- dcap-qvl (cargo)
- dstack-mr (go install github.com/kvinwang/dstack-mr@0.3.5)

## Steps to verify quote

1. Get the quote from the attestation service
2. Get the event log from the attestation service
3. Get the pccs url from the attestation service
4. Get the expected mr data from the attestation service
5. Verify the quote
6. Replay the rtmrs
7. Verify the rtmrs
