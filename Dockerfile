FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Define build arguments for version
ARG VERSION="dev"

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server

# Final stage
FROM alpine:latest

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /server /app/server

# Create directory for certificates
RUN mkdir -p /app/certs

# Define build arguments for configuration
ARG MIN_PORT=8000
ARG MAX_PORT=9000
ARG NODE_IPS="127.0.0.1"
ARG VERSION="dev"

# Set default environment variables
ENV NODE_IPS=${NODE_IPS} \
    MIN_PORT=${MIN_PORT} \
    MAX_PORT=${MAX_PORT} \
    CERT_FILE="/app/certs/certificate.pem" \
    KEY_FILE="/app/certs/private-key.pem" \
    VERSION=${VERSION}

# Add version label
LABEL version=${VERSION} \
      maintainer="SkyQuakers" \
      description="Dynamic Port Forwarder with SSL termination"

# Expose port range (configurable via MIN_PORT and MAX_PORT build args)
EXPOSE ${MIN_PORT}-${MAX_PORT}

# Run the application
CMD ["/app/server"] 