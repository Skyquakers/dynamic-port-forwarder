# Dynamic Port Forwarder

A TCP port forwarder with SSL termination written in Go. The application dynamically listens on a range of ports and forwards HTTPS to HTTP and WSS to WS.

## Features

- Routes HTTPS traffic to HTTP backends
- Routes WSS (WebSocket Secure) traffic to WS backends
- Configurable target node IPs
- Configurable port range
- SSL termination

## Configuration

The application is configured through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_IPS` | Comma-separated list of backend node IPs | 127.0.0.1 |
| `MIN_PORT` | Minimum port in the listening range | 8000 |
| `MAX_PORT` | Maximum port in the listening range | 9000 |
| `CERT_FILE` | Path to the SSL certificate file | (required) |
| `KEY_FILE` | Path to the SSL private key file | (required) |

## Docker

### Building the Docker Image

```bash
docker build -t dynamic-port-forwarder .
```

You can specify build arguments to customize the default configuration:

```bash
docker build -t dynamic-port-forwarder \
  --build-arg MIN_PORT=8000 \
  --build-arg MAX_PORT=9000 \
  --build-arg NODE_IPS="10.0.0.1,10.0.0.2" \
  --build-arg VERSION="1.0.0" \
  .
```

You can override these paths using the `CERT_FILE` and `KEY_FILE` environment variables.

## Building

```bash
go build -o server ./cmd/server
```

## Running

```bash
export NODE_IPS=10.0.0.1,10.0.0.2
export MIN_PORT=8000
export MAX_PORT=9000
export CERT_FILE=/path/to/certificate.pem
export KEY_FILE=/path/to/private-key.pem
./server
```

## How It Works

1. The forwarder listens on all ports in the specified range with HTTPS/WSS.
2. When a request arrives, it terminates the SSL connection.
3. The request is forwarded to the corresponding port on one of the configured backend nodes.
4. For regular HTTP requests, it forwards the request as HTTP.
5. For WebSocket connections, it forwards the connection as WS.

## License

[MIT License](LICENSE) 