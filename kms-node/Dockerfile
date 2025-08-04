# ----- Build stage -----
FROM rust:1.85.0 AS builder

WORKDIR /usr/src/app

# Copy the full project
COPY . .

# Accept and export build-time feature flags
ARG FEATURE_FLAGS
ENV FEATURE_FLAGS=$FEATURE_FLAGS

# Build the Rust binary with optional features
RUN cargo build --release --features "$FEATURE_FLAGS"

# ----- Runtime stage -----
FROM debian:bookworm-slim

# Define all runtime ENV variables
ENV P2P_NODE_NAME=""
ENV P2P_NODE_PORT=""
ENV P2P_PROTOCOL_NAME=""
ENV P2P_IDENTIFY_PROTOCOL_VERSION=""
ENV PCCS_URL=""
ENV APP_COMPOSE_HASH=""
ENV EXPECTED_MR_VALUE_MRTD=""
ENV EXPECTED_MR_VALUE_RTMR0=""
ENV EXPECTED_MR_VALUE_RTMR1=""
ENV EXPECTED_MR_VALUE_RTMR2=""

# Set default key path - will be overridden by volume mount
ENV P2P_NODE_KEY_PATH="/data/node_key.pem"
ENV RUST_LOG=info

# Install SSL certs (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd --gid 1000 enigma && \
    useradd --uid 1000 --gid enigma --shell /bin/bash --create-home enigma

# Create /data directory with correct ownership and permissions
RUN mkdir /data && \
    chown enigma:enigma /data && \
    chmod 700 /data

COPY --from=builder /usr/src/app/target/release/enigma-kms-node /data/enigma-kms-node

# Set ownership and execute permissions on the binary
RUN chown enigma:enigma /data/enigma-kms-node && \
    chmod +x /data/enigma-kms-node

# Add /data to PATH so the binary can be found
ENV PATH="/data:${PATH}"

# Switch to non-root user
USER enigma

# Set working directory to /data where user has permissions
WORKDIR /data

# Entrypoint
CMD ["enigma-kms-node"]
