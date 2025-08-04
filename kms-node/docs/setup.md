# Setup

## Steps to setup the node

1. Create a `.env` file in the root directory of the project.

    ```bash
        cp .env.example .env
    ```

2. Set the env variables in the `.env` file.
3. Set the P2P_NODE_KEY_PATH to the path of the key file
in the `.env` file.
4. Build the node using docker :

    ```bash
        FEATURE_FLAGS="persistent-connection local-quote-verification" \
        docker-compose --env-file .env build
    ```

5. Run the node using docker :

    ```bash
        docker-compose --env-file .env up

        # Or

        docker run -v ./data/keys/node_key_node_3.bin:/data/node_key.pem:ro \
        -e P2P_NODE_PORT=9004 \
        -e P2P_NODE_NAME="node_d" \
        -e P2P_PROTOCOL_NAME="/enigma-kms-p2p/message/1.0.0" \
        -e P2P_IDENTIFY_PROTOCOL_VERSION="/encrypted-network/1.0.0" \
        -e PCCS_URL="https://your-pccs-server.com" \
        -e APP_COMPOSE_HASH="your-app-compose-hash" \
        -e EXPECTED_MR_VALUE_MRTD="your-mrtd-value" \
        -e EXPECTED_MR_VALUE_RTMR0="your-rtmr0-value" \
        -e EXPECTED_MR_VALUE_RTMR1="your-rtmr1-value" \
        -e EXPECTED_MR_VALUE_RTMR2="your-rtmr2-value" \
        -p 9004:9004 \
        ocdbytes/enigma-kms-p2p:latest
    ```
