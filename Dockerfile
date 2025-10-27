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
COPY start.sh .

# Make startup script executable and verify it exists
RUN chmod +x start.sh && ls -la /app/start.sh && head -1 /app/start.sh

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV ENABLE_WARP=true

EXPOSE 8000

# Use the startup script that initializes WARP and then starts the app
CMD ["bash", "/app/start.sh"]
