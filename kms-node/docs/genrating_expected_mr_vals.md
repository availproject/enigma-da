# Generating Expected MR values

Pre-Requisites :

- Docker
- dstack-mr (go install github.com/kvinwang/dstack-mr@0.3.5)

## Steps to generate expected mr values

1. Clone the meta-dstack repository and checkout the version you want to use then
build.

    ```sh
    git clone https://github.com/Dstack-TEE/meta-dstack.git
    cd meta-dstack
    git checkout v0.3.6

    # Build MR values
    git submodule update --init --recursive
    cd repro-build && ./repro-build.sh -n
    ```

2. This will return a zip file and then unzip it. It will contain a metadata.json
file.

    ```sh
    dstack-mr -cpu 1 -memory 2G -json -metadata path_to_metadata.json
    ```

    Example Output :

    ```json
    {
        "mrtd": "c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd",
        "rtmr0": "85e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb6547",
        "rtmr1": "154e08f5c1f7b1fce4cbfe1c14f3ba67b70044ede2751487279cd1f2e4239dee99a6d45e24ebde6b6a6f5ae49878e0e6",
        "rtmr2": "9edcd363660e85b71c318324996dda756c372d9f6960edbfa863b1e684822eb48dd95e218ae2b78e51ef97f3b8f5c9dc",
        "mr_aggregated": "aa2efa9277cf47d760b965479547fe598e1fce1e0126f00a836655f15d7b985d",
        "mr_image": "fce246f1773ee1374a3fcc3c0020e9715e24f6d9036a35ea8aa141f55e9f39d1"
    }
    ```
