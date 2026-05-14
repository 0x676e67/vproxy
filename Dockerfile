# Build stage
FROM rust:alpine3.20 AS builder

RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:3.16

RUN apk add --no-cache iproute2 procps curl

# Copy vproxy binary
COPY --from=builder /app/target/release/vproxy /usr/local/bin/vproxy

# Install cloudflared
RUN curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && \
    chmod +x /usr/local/bin/cloudflared

EXPOSE 9090

# Run both vproxy and cloudflared with tunnel token
CMD sh -c 'vproxy run --bind 0.0.0.0:9090 http & cloudflared tunnel run --token eyJhIjoiNzEzMTEwODBmMDcxZTFkZWQ5NmQzNGZkNWIxMzMwZTAiLCJ0IjoiMjJhYjdkOWYtMjFhZC00NDQ0LWJlYzItZmQ5MGU3ZTYyYmQ2IiwicyI6Ik0yTXhZVGRtTXpJdE5tRTVOeTAwTURRekxUazRNRGN0WlRNNVpqUTJOamhqTkRNeiJ9'
