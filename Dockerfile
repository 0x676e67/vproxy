# Build stage
FROM rust:alpine3.20 AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the project in release mode
RUN cargo build --release

# Runtime stage
FROM alpine:3.16

# Install runtime dependencies
RUN apk add --no-cache iproute2 procps

# Copy the built binary from the builder stage
COPY --from=builder /app/target/release/vproxy /usr/local/bin/vproxy

# Expose port 9090 for TCP proxy access
EXPOSE 9090

# Run vproxy HTTP proxy on 0.0.0.0:9090
CMD ["vproxy", "run", "--bind", "0.0.0.0:9090", "http"]
