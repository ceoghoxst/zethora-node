# --- Build Stage ---
FROM rust:latest AS builder

# Install required dependencies for Zethora (Clang, CMake, Protobuf)
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    clang \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/zethora
COPY . .

# Build the node in release mode
RUN CARGO_BUILD_JOBS=4 cargo build --release --bin kaspad

# --- Runtime Stage ---
FROM debian:bookworm-slim

# Install runtime dependencies (OpenSSL and RocksDB need these)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/zethora/target/release/kaspad /app/kaspad

# Expose the P2P and gRPC ports
EXPOSE 26611
EXPOSE 26610

# Default command to run the node
ENTRYPOINT ["/app/kaspad"]
CMD ["--devnet", "--utxoindex", "--enable-unsynced-mining", "--disable-upnp"]