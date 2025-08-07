# Setup

## Steps to setup the node

1. Create a `.env` file in the root directory of the project.

    ```bash
        cp .env.example .env
    ```

2. Set the env variables in the `.env` file.
3. Copy the key file to the same path inside the project as defined in
the `.env` file.
4. Build the node using docker :

    ```bash
        docker-compose --env-file .env build
    ```

5. Run the node using docker :

    ```bash
        docker-compose --env-file .env up
    ```
