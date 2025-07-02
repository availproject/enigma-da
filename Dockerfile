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
RUN cargo build --release

# Create a smaller runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
  libssl-dev \
  ca-certificates \
  librocksdb-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binaries from builder
COPY --from=builder /usr/src/app/target/release/encifher-encryption-service /app/encifher-encryption-service

# Copy and set permissions for startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

ENV RUST_LOG=info

CMD ["/app/start.sh"]