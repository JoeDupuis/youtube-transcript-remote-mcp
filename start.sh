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

    # Show WARP settings
    echo "WARP Settings:"
    warp-cli --accept-tos settings 2>/dev/null || echo "Unable to get WARP settings"

    # Export proxy environment variables for processes that don't use explicit proxy config
    export ALL_PROXY=socks5://127.0.0.1:40000
    export HTTP_PROXY=socks5://127.0.0.1:40000
    export HTTPS_PROXY=socks5://127.0.0.1:40000

    echo "✓ WARP setup complete!"
    echo "All traffic will be routed through CloudFlare WARP"
else
    echo "CloudFlare WARP is disabled. Running without proxy..."
fi

# Start the Python application
echo "Starting YouTube Transcript MCP server..."
exec python youtube_transcript_mcp.py
