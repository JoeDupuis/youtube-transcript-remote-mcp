# YouTube Transcript MCP Server

An MCP (Model Context Protocol) server that provides YouTube transcript fetching capabilities with Google OAuth 2.0 authentication. Only authorized users can access transcript data.

## Features

- Fetch YouTube video transcripts from video IDs or full URLs
- Support for both manually created and auto-generated transcripts
- Optional timestamp inclusion for each transcript segment
- List available transcripts for any video
- Google OAuth 2.0 authentication with email-based authorization
- Automatic video ID extraction from various YouTube URL formats
- **CloudFlare WARP integration to prevent IP bans** - Routes all requests through CloudFlare's network
- Automatic retry with IP rotation on rate limit errors

## Installation

1. Clone this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Google OAuth Setup

### 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google Identity API (if not already enabled)

### 2. Create OAuth 2.0 Credentials

1. Navigate to **APIs & Services > Credentials**
2. Click **Create Credentials > OAuth client ID**
3. Select **Web application** as the application type
4. Add authorized redirect URIs:
   - For local development: `http://localhost:8080`
   - For production: Your application's callback URL
5. Click **Create**
6. Download the client configuration or note your **Client ID**

### 3. Configure Environment Variables

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Edit `.env` and add your configuration:

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
AUTHORIZED_EMAILS=user1@gmail.com,user2@example.com
```

- `GOOGLE_CLIENT_ID`: Your OAuth 2.0 client ID from Google Cloud Console
- `AUTHORIZED_EMAILS`: Comma-separated list of email addresses allowed to use the service

## CloudFlare WARP Integration

This server includes built-in CloudFlare WARP support to prevent IP-based rate limiting and bans from Google/YouTube. WARP routes all HTTP requests through CloudFlare's global network, masking your real server IP.

### How It Works

```
Your Server → WARP Client → CloudFlare Network → Google/YouTube
(Real IP)    (SOCKS5 Proxy)  (CloudFlare IPs)   (Sees CF IP)
```

**Benefits:**
- ✅ Google sees CloudFlare's IPs instead of your real server IP
- ✅ Automatic IP rotation through CloudFlare's network
- ✅ No CloudFlare account or dashboard setup required (uses free public WARP)
- ✅ Automatic retry with WARP reconnection on rate limit errors
- ✅ Better rate limits (CloudFlare IPs are trusted by Google)

### Configuration

WARP is **enabled by default**. You can control it with the `ENABLE_WARP` environment variable:

```env
# Enable WARP (default)
ENABLE_WARP=true

# Disable WARP (use direct connections)
ENABLE_WARP=false
```

### How It Prevents IP Bans

1. **IP Masking**: All requests appear to come from CloudFlare's network, not your server
2. **Automatic Rotation**: WARP periodically rotates exit IPs based on CloudFlare's routing
3. **Retry Logic**: If a rate limit error occurs:
   - The server automatically reconnects to WARP (getting a likely different IP)
   - Retries the request up to 3 times
   - If still blocked, returns an error

### Manual IP Change

If you need to manually change the IP (e.g., if Google blocks one CloudFlare IP):

```bash
# Restart the container to reconnect WARP with a new IP
docker-compose restart youtube-transcript-mcp

# Or use docker restart
docker restart youtube-transcript-remote-mcp-youtube-transcript-mcp-1
```

Inside the container, you can also manually restart WARP:

```bash
docker exec -it youtube-transcript-remote-mcp-youtube-transcript-mcp-1 bash
warp-cli disconnect
warp-cli connect
warp-cli status
```

### Monitoring WARP

Check WARP status in the container logs:

```bash
docker-compose logs -f youtube-transcript-mcp
```

You should see:
```
Starting YouTube Transcript MCP with CloudFlare WARP support...
CloudFlare WARP is enabled. Setting up WARP...
Starting WARP daemon...
Registering WARP client...
Connecting to WARP...
✓ WARP connected successfully!
✓ WARP setup complete!
All traffic will be routed through CloudFlare WARP
```

### Disabling WARP

If you want to disable WARP and use direct connections:

1. Set `ENABLE_WARP=false` in your `.env` file or `docker-compose.yml`
2. Rebuild and restart: `docker-compose up -d --build`

### Requirements

- Docker with `NET_ADMIN` and `SYS_MODULE` capabilities (already configured in `docker-compose.yml`)
- No CloudFlare account needed for basic usage
- IPv6 support (enabled automatically in the container)

### Advanced: CloudFlare Teams (Optional)

For enterprise features like usage analytics, custom policies, and device management:

1. Create a [CloudFlare Zero Trust account](https://dash.teams.cloudflare.com/) (free for up to 50 users)
2. Get your Teams enrollment token from the dashboard
3. Add to `.env`:
   ```env
   WARP_TEAMS_ENROLLMENT_TOKEN=your-token-here
   ```
4. Modify `start.sh` to use: `warp-cli teams-enroll ${WARP_TEAMS_ENROLLMENT_TOKEN}`

**Note**: For basic IP masking and preventing bans, the free public WARP is sufficient.

## Running the Server

### Option 1: Docker (Recommended)

1. Build and run with docker-compose:

```bash
docker-compose up -d
```

2. Or build and run manually:

```bash
docker build -t youtube-transcript-mcp .
docker run -p 8000:8000 --env-file .env youtube-transcript-mcp
```

The server will be available at: `http://localhost:8000/sse`

### Option 2: Direct Python

The server runs with SSE (Server-Sent Events) transport on port 8000 by default:

```bash
python youtube_transcript_mcp.py
```

The server will be available at: `http://localhost:8000/sse`

For MCP Inspector or other MCP clients, use:
- **Transport Type:** SSE
- **URL:** `http://localhost:8000/sse`

## Available Tools

### 1. `youtube_get_transcript`

Fetches the transcript for a YouTube video.

**Parameters:**
- `video_input` (string, required): YouTube video ID or full URL
  - Examples: `dQw4w9WgXcQ` or `https://youtube.com/watch?v=dQw4w9WgXcQ`
- `cursor` (integer, optional, default: 0): Starting segment index for pagination

**Returns:** Markdown-formatted transcript with timestamps

**How Pagination Works:**
- The tool automatically fits as many segments as possible within the MCP response size limit (25,000 characters)
- If the transcript is too long, it returns a chunk and tells you there's more
- Use the `cursor` parameter from the response to fetch the next chunk

**Example (start from beginning):**
```json
{
  "video_input": "dQw4w9WgXcQ"
}
```

**Example (fetch next page):**
```json
{
  "video_input": "dQw4w9WgXcQ",
  "cursor": 250
}
```

**Response Format:**
When the transcript is paginated, the response includes:
- `Showing segments X-Y of Z`: Current page range
- `Has more`: Whether there are more segments to fetch
- `Next cursor`: Value to use for fetching the next batch (only if has_more is true)

### 2. `youtube_list_available_transcripts`

Lists all available transcripts for a YouTube video.

**Parameters:**
- `video_input` (string, required): YouTube video ID or full URL
- `auth_token` (string, required): Google OAuth 2.0 ID token

**Returns:** Markdown-formatted list of available transcripts with language information

**Example:**
```json
{
  "video_input": "https://youtu.be/dQw4w9WgXcQ",
  "auth_token": "your-google-oauth-token"
}
```

## Supported URL Formats

The server automatically extracts video IDs from these URL formats:

- `https://www.youtube.com/watch?v=VIDEO_ID`
- `https://youtu.be/VIDEO_ID`
- `https://www.youtube.com/embed/VIDEO_ID`
- `https://www.youtube.com/v/VIDEO_ID`
- Direct video ID: `VIDEO_ID`

## Authentication Flow

1. User authenticates with Google OAuth 2.0
2. Client obtains an ID token from Google
3. Client passes the ID token in the `auth_token` parameter
4. Server validates the token with Google
5. Server checks if the user's email is in the authorized list
6. If authorized, the tool executes; otherwise, access is denied

## Error Handling

The server provides clear error messages for common issues:

- **Invalid/expired token**: "Invalid or expired authentication token"
- **Unauthorized user**: "Access denied. User X is not authorized"
- **Video unavailable**: "Video is unavailable. It may be private, deleted, or the ID is incorrect"
- **No transcripts**: "No transcripts available for this video"
- **Transcripts disabled**: "Transcripts are disabled for this video"

## Security Considerations

- OAuth tokens are validated on every request
- Only users in the `AUTHORIZED_EMAILS` list can access tools
- Client secrets should never be committed to version control
- Store `.env` securely and never share publicly
- The server is read-only and cannot modify YouTube data

## Limitations

- Currently only supports English transcripts
- Requires internet connection to fetch transcripts and validate tokens
- Subject to YouTube's rate limits and availability (mitigated by CloudFlare WARP)
- Very long transcripts should use pagination to stay within MCP response size limits
- WARP requires Docker capabilities: NET_ADMIN and SYS_MODULE (already configured)

## License

MIT
