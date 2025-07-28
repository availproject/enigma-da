# FROM rust:1.79 as builder
FROM rustlang/rust:nightly as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
  clang \
  libclang-dev \
  libssl-dev \
  pkg-config \
  librocksdb-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

# Install dependencies and build
RUN cargo build --release --features persistent-connection

# Create a smaller runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
  libssl-dev \
  ca-certificates \
  librocksdb-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG SERVER_PORT
ARG SERVER_HOST
ARG P2P_PORT
ARG P2P_NODE_NAME
ARG P2P_PROTOCOL_NAME
ARG P2P_IDENTIFY_PROTOCOL_VERSION
ARG NUMBER_OF_P2P_NETWORK_NODES
ARG SHARD_REQUEST_INTERVAL_SECS
ARG SHARD_REQUEST_RETRY_COUNT
ARG SHARD_CLEANUP_INTERVAL_HOURS
ARG JOB_QUEUE_SIZE
ARG DATABASE_PATH

ENV SERVER_PORT=${SERVER_PORT}
ENV SERVER_HOST=${SERVER_HOST}
ENV P2P_PORT=${P2P_PORT}
ENV P2P_NODE_NAME=${P2P_NODE_NAME}
ENV P2P_PROTOCOL_NAME=${P2P_PROTOCOL_NAME}
ENV P2P_IDENTIFY_PROTOCOL_VERSION=${P2P_IDENTIFY_PROTOCOL_VERSION}
ENV NUMBER_OF_P2P_NETWORK_NODES=${NUMBER_OF_P2P_NETWORK_NODES}
ENV SHARD_REQUEST_INTERVAL_SECS=${SHARD_REQUEST_INTERVAL_SECS}
ENV SHARD_REQUEST_RETRY_COUNT=${SHARD_REQUEST_RETRY_COUNT}
ENV SHARD_CLEANUP_INTERVAL_HOURS=${SHARD_CLEANUP_INTERVAL_HOURS}
ENV JOB_QUEUE_SIZE=${JOB_QUEUE_SIZE}
ENV DATABASE_PATH=${DATABASE_PATH}

# Copy the built binaries from builder
COPY --from=builder /usr/src/app/target/release/service /app/service
COPY --from=builder /usr/src/app/peers.json /app/peers.json

# Copy and set permissions for startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

CMD ["/app/start.sh"]