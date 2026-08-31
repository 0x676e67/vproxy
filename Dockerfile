# Build stage
FROM rust:alpine3.20 AS builder

RUN apk add --no-cache musl-dev
WORKDIR /app

# Build vproxy
COPY . .
RUN cargo build --release

# Build bore from source
RUN cargo install bore-cli

# Runtime stage
FROM alpine:3.16

RUN apk add --no-cache iproute2 procps

# Copy binaries
COPY --from=builder /app/target/release/vproxy /usr/local/bin/vproxy
COPY --from=builder /usr/local/cargo/bin/bore /usr/local/bin/bore

EXPOSE 9090

# Run vproxy and bore tunnel
CMD sh -c 'vproxy run --bind 0.0.0.0:9090 http & bore local 9090 --to bore.pub'
