# Build stage
FROM rust:alpine3.20 AS builder

RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:3.16

RUN apk add --no-cache iproute2 procps curl wget

# Copy vproxy binary
COPY --from=builder /app/target/release/vproxy /usr/local/bin/vproxy

# Install bore - use direct GitHub release download
RUN wget -O /usr/local/bin/bore https://github.com/ekzhang/bore/releases/download/v0.5.1/bore-x86_64-unknown-linux-musl && \
    chmod +x /usr/local/bin/bore

EXPOSE 9090

# Run both vproxy and bore tunnel
CMD sh -c 'vproxy run --bind 0.0.0.0:9090 http & bore local 9090 --to bore.pub'
