# YouTube Transcript MCP Server

An MCP (Model Context Protocol) server that provides YouTube transcript fetching capabilities with Google OAuth 2.0 authentication. Only authorized users can access transcript data.

## Features

- Fetch YouTube video transcripts from video IDs or full URLs
- Support for both manually created and auto-generated transcripts
- Optional timestamp inclusion for each transcript segment
- List available transcripts for any video
- Google OAuth 2.0 authentication with email-based authorization
- Automatic video ID extraction from various YouTube URL formats

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

Fetches the transcript for a YouTube video with optional pagination support.

**Parameters:**
- `video_input` (string, required): YouTube video ID or full URL
  - Examples: `dQw4w9WgXcQ` or `https://youtube.com/watch?v=dQw4w9WgXcQ`
- `cursor` (integer, optional, default: 0): Starting segment index for pagination
- `page_size` (integer, optional, default: null): Number of segments to return per page
  - If not specified, returns the entire transcript
  - Useful for handling very long transcripts within MCP response size limits

**Returns:** Markdown-formatted transcript with timestamps and pagination metadata

**Example (full transcript):**
```json
{
  "video_input": "dQw4w9WgXcQ"
}
```

**Example (paginated):**
```json
{
  "video_input": "dQw4w9WgXcQ",
  "cursor": 0,
  "page_size": 100
}
```

**Pagination Response Format:**
The response includes pagination metadata:
- `Showing segments X-Y of Z`: Current page range
- `Has more`: Whether there are more segments to fetch
- `Next cursor`: Value to use for the next page (if has_more is true)

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
- Subject to YouTube's rate limits and availability
- Very long transcripts should use pagination to stay within MCP response size limits

## License

MIT
