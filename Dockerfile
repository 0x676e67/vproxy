# Build stage
FROM rust:alpine3.20 AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the project
RUN cargo build --release

# Runtime stage
FROM alpine:3.16

# Copy the built binary from the builder stage
COPY --from=builder /app/target/release/vproxy /bin/vproxy

# Iproute2 and procps are needed for the vproxy to work
RUN apk add --no-cache iproute2 procps

# Set the entrypoint
ENTRYPOINT ["/bin/vproxy"]
