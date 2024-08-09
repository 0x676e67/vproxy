# Build stage
FROM rust:1.76-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the project
RUN cargo build --release

# Identify and copy only the needed shared libraries
RUN mkdir -p /app/lib && \
    ldd /app/target/release/vproxy | \
    grep "=> /" | \
    awk '{print $3}' | \
    sort -u | \
    xargs -I '{}' cp -v '{}' /app/lib/

# Runtime stage
FROM scratch

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/target/release/vproxy /app/vproxy

# Copy only the necessary shared libraries
COPY --from=builder /app/lib /lib

# Set the entrypoint
ENTRYPOINT ["/app/vproxy"]