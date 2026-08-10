# seam — post-quantum encrypted UDP transport + CLI
#
# This image runs `seam serve`, the persistent server daemon (no SSH needed
# on the remote side). Built WITHOUT the `fuse` feature — matching the
# prebuilt release binaries — so the image has no libfuse dependency and
# `seam mount` isn't available from inside a container built this way.
#
# Build:
#   docker build -t seam .
#
# Run (persist the identity key across restarts so TOFU pins on clients
# don't break every time the container restarts):
#   docker volume create seam-data
#   docker run -d --name seam \
#     -p 2222:2222/udp \
#     -v seam-data:/home/seam/.config \
#     seam serve --port 2222

FROM rust:1-bookworm AS builder
WORKDIR /build

# Cache dependency compilation separately from source changes: build once
# against stub sources so `cargo build` downloads and compiles every
# dependency into a layer that's reused as long as Cargo.toml/Cargo.lock
# don't change, then overlay the real source and rebuild just the crate.
# benches/ must exist for Cargo to parse the manifest (Cargo.toml declares
# [[bench]] targets), even though this build only needs the `seam` bin.
COPY Cargo.toml Cargo.lock ./
COPY benches ./benches
RUN mkdir -p src/bin/seam \
    && echo "fn main() {}" > src/bin/seam/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin seam

COPY src ./src
RUN touch src/lib.rs src/bin/seam/main.rs \
    && cargo build --release --bin seam

FROM debian:bookworm-slim
RUN groupadd -r seam && useradd -r -g seam -m -d /home/seam -s /usr/sbin/nologin seam
COPY --from=builder /build/target/release/seam /usr/local/bin/seam

USER seam
WORKDIR /home/seam
ENV HOME=/home/seam

# Default seam serve port (UDP). Override with `seam serve --port <N>`.
EXPOSE 2222/udp

# Identity key and audit log persist under $HOME/.config and $HOME/.local —
# mount a volume there (see usage note above) if you want them to survive
# container restarts/recreation.
VOLUME ["/home/seam/.config", "/home/seam/.local"]

ENTRYPOINT ["seam"]
CMD ["serve", "--port", "2222", "--bind", "0.0.0.0"]
