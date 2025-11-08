FROM python:3.11-slim

WORKDIR /app

# Install CloudFlare WARP and dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    && curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update \
    && apt-get install -y cloudflare-warp \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY youtube_transcript_mcp.py .

# Create startup script directly in the image
RUN cat > /usr/local/bin/start-warp.sh << 'EOFSCRIPT' && chmod +x /usr/local/bin/start-warp.sh \
&& cat /usr/local/bin/start-warp.sh
#!/usr/bin/env bash
set -e

echo "Starting YouTube Transcript MCP with CloudFlare WARP support..."

# Check if WARP should be enabled
ENABLE_WARP=${ENABLE_WARP:-true}

if [ "$ENABLE_WARP" = "true" ]; then
    echo "CloudFlare WARP is enabled. Setting up WARP..."

    # Start the WARP daemon
    echo "Starting WARP daemon..."
    warp-svc &
    WARP_PID=$!

    # Wait for daemon to start
    sleep 2

    # Check if daemon is running
    if ! kill -0 $WARP_PID 2>/dev/null; then
        echo "ERROR: WARP daemon failed to start"
        exit 1
    fi

    # Register WARP (this is idempotent - won't re-register if already registered)
    echo "Registering WARP client..."
    warp-cli --accept-tos register 2>/dev/null || echo "WARP already registered"

    # Enable WARP proxy mode (SOCKS5)
    echo "Setting WARP to proxy mode..."
    warp-cli --accept-tos set-mode proxy

    # Connect to WARP
    echo "Connecting to WARP..."
    warp-cli --accept-tos connect

    # Wait for connection to establish
    echo "Waiting for WARP connection..."
    MAX_RETRIES=30
    RETRY_COUNT=0

    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "Unknown")

        if echo "$STATUS" | grep -q "Connected"; then
            echo "✓ WARP connected successfully!"
            echo "WARP Status: $STATUS"
            break
        fi

        RETRY_COUNT=$((RETRY_COUNT + 1))
        echo "Waiting for WARP connection... (attempt $RETRY_COUNT/$MAX_RETRIES)"
        sleep 2
    done

    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        echo "ERROR: WARP failed to connect after $MAX_RETRIES attempts"
        echo "WARP Status: $(warp-cli --accept-tos status 2>/dev/null || echo 'Unable to get status')"
        exit 1
    fi

    # Export proxy environment variables
    export ALL_PROXY=socks5://127.0.0.1:40000
    export HTTP_PROXY=socks5://127.0.0.1:40000
    export HTTPS_PROXY=socks5://127.0.0.1:40000

    echo "✓ WARP setup complete!"
    echo "All traffic will be routed through CloudFlare WARP"

    # Test and display the external IP
    echo ""
    echo "Testing WARP connection - Checking external IP..."
    EXTERNAL_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "Unable to fetch")
    echo "External IP (via WARP): $EXTERNAL_IP"

    # Also show CloudFlare trace for more details
    echo ""
    echo "CloudFlare trace info:"
    curl -s --max-time 10 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep -E "^(ip|loc|warp)" || echo "Unable to fetch trace"
    echo ""
else
    echo "CloudFlare WARP is disabled. Running without proxy..."

    # Show real IP when WARP is disabled for comparison
    echo ""
    echo "Testing direct connection - Checking external IP..."
    EXTERNAL_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "Unable to fetch")
    echo "External IP (direct): $EXTERNAL_IP"
    echo ""
fi

# Start the Python application
echo "Starting YouTube Transcript MCP server..."
exec python youtube_transcript_mcp.py
EOFSCRIPT

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV ENABLE_WARP=true

EXPOSE 8000

# Use the startup script
CMD ["/usr/local/bin/start-warp.sh"]
