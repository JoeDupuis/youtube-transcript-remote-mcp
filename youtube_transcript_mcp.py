#!/usr/bin/env python3

from typing import Optional, List
import os
import re
import secrets
import time
import json
import asyncio
import aiosqlite
from dotenv import load_dotenv
from pydantic import AnyHttpUrl
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    AccessToken,
    AuthorizationCode,
    RefreshToken,
    AuthorizationParams,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.auth.routes import create_auth_routes
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import (
    TranscriptsDisabled,
    NoTranscriptFound,
    VideoUnavailable
)
from google.oauth2 import id_token
from google.auth.transport import requests
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

load_dotenv()

AUTHORIZED_EMAILS = os.getenv("AUTHORIZED_EMAILS", "").split(",")
AUTHORIZED_EMAILS = [email.strip() for email in AUTHORIZED_EMAILS if email.strip()]
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

CHARACTER_LIMIT = 25000

async def init_database(db_path: str = "oauth_tokens.db"):
    """Initialize the SQLite database with required tables."""
    async with aiosqlite.connect(db_path) as db:
        # Create refresh_tokens table first (referenced by access_tokens)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                resource TEXT
            )
        """)

        # Create access_tokens table with foreign key to refresh_tokens
        await db.execute("""
            CREATE TABLE IF NOT EXISTS access_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                resource TEXT,
                refresh_token TEXT,
                FOREIGN KEY (refresh_token) REFERENCES refresh_tokens(token) ON DELETE CASCADE
            )
        """)

        # Create clients table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_data TEXT NOT NULL
            )
        """)

        # Create indexes for faster token lookups
        await db.execute("CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)")

        await db.commit()

class GoogleOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):

    def __init__(self, server_url: str, db_path: str = "oauth_tokens.db"):
        self.server_url = server_url
        self.db_path = db_path
        # Keep short-lived data in memory
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.state_mapping: dict[str, dict] = {}
        self.user_emails: dict[str, str] = {}

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT client_data FROM clients WHERE client_id = ?",
                (client_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    client_data = json.loads(row[0])
                    return OAuthClientInformationFull(**client_data)
                return None

    async def register_client(self, client_info: OAuthClientInformationFull):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO clients (client_id, client_data) VALUES (?, ?)",
                (client_info.client_id, json.dumps(client_info.model_dump(mode='json')))
            )
            await db.commit()

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = params.state or secrets.token_hex(16)

        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "client_id": client.client_id,
            "resource": params.resource,
        }

        google_auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={GOOGLE_CLIENT_ID}&"
            f"redirect_uri={self.server_url}/google/callback&"
            f"response_type=code&"
            f"scope=openid email&"
            f"state={state}"
        )

        return google_auth_url

    async def handle_google_callback(self, request: Request) -> Response:
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            raise HTTPException(400, "Missing code or state")

        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state")

        import httpx
        token_response = await httpx.AsyncClient().post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": f"{self.server_url}/google/callback",
                "grant_type": "authorization_code",
            }
        )

        if token_response.status_code != 200:
            raise HTTPException(400, "Failed to exchange code for token")

        token_data = token_response.json()
        google_id_token = token_data.get("id_token")

        try:
            idinfo = id_token.verify_oauth2_token(google_id_token, requests.Request(), GOOGLE_CLIENT_ID)
            email = idinfo.get('email')

            if not email or email.lower() not in [auth_email.lower() for auth_email in AUTHORIZED_EMAILS]:
                raise HTTPException(403, f"Access denied. User {email} is not authorized")

            mcp_code = f"mcp_{secrets.token_hex(16)}"
            auth_code = AuthorizationCode(
                code=mcp_code,
                client_id=state_data["client_id"],
                redirect_uri=state_data["redirect_uri"],
                redirect_uri_provided_explicitly=state_data["redirect_uri_provided_explicitly"],
                expires_at=time.time() + 300,
                scopes=["youtube_transcript"],
                code_challenge=state_data["code_challenge"],
                resource=state_data.get("resource"),
            )
            self.auth_codes[mcp_code] = auth_code
            self.user_emails[mcp_code] = email

            redirect_uri = construct_redirect_uri(state_data["redirect_uri"], code=mcp_code, state=state)
            del self.state_mapping[state]

            return RedirectResponse(url=redirect_uri, status_code=302)

        except Exception as e:
            raise HTTPException(403, f"Google authentication failed: {str(e)}")

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        mcp_token = f"mcp_{secrets.token_hex(32)}"
        mcp_refresh_token = f"mcp_refresh_{secrets.token_hex(32)}"

        email = self.user_emails.get(authorization_code.code, "unknown")

        # Create tokens in database
        async with aiosqlite.connect(self.db_path) as db:
            # Create refresh token first (expires in 90 days for security)
            refresh_token_expiry = int(time.time()) + (90 * 24 * 3600)  # 90 days
            await db.execute(
                """INSERT INTO refresh_tokens (token, client_id, subject, scopes, expires_at, resource)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (mcp_refresh_token, client.client_id, email, json.dumps(authorization_code.scopes),
                 refresh_token_expiry, authorization_code.resource)
            )

            # Create access token with reference to refresh token
            expires_at = int(time.time()) + 3600
            await db.execute(
                """INSERT INTO access_tokens (token, client_id, subject, scopes, expires_at, resource, refresh_token)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mcp_token, client.client_id, email, json.dumps(authorization_code.scopes),
                 expires_at, authorization_code.resource, mcp_refresh_token)
            )

            await db.commit()

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
            refresh_token=mcp_refresh_token,
        )

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """SELECT token, client_id, subject, scopes, expires_at, resource
                   FROM access_tokens WHERE token = ?""",
                (token,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None

                token_str, client_id, subject, scopes_json, expires_at, resource = row

                # Check if token is expired
                if expires_at and expires_at < time.time():
                    await db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
                    await db.commit()
                    return None

                return AccessToken(
                    token=token_str,
                    client_id=client_id,
                    subject=subject,
                    scopes=json.loads(scopes_json),
                    expires_at=expires_at,
                    resource=resource,
                )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> Optional[RefreshToken]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """SELECT token, client_id, subject, scopes, expires_at, resource
                   FROM refresh_tokens WHERE token = ?""",
                (refresh_token,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None

                token_str, client_id, subject, scopes_json, expires_at, resource = row

                # Verify the token belongs to the requesting client
                if client_id != client.client_id:
                    return None

                # Check if token is expired
                if expires_at and expires_at < time.time():
                    await db.execute("DELETE FROM refresh_tokens WHERE token = ?", (refresh_token,))
                    await db.commit()
                    return None

                return RefreshToken(
                    token=token_str,
                    client_id=client_id,
                    subject=subject,
                    scopes=json.loads(scopes_json),
                    expires_at=expires_at,
                    resource=resource,
                )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        async with aiosqlite.connect(self.db_path) as db:
            # Verify the refresh token is still valid
            async with db.execute(
                "SELECT 1 FROM refresh_tokens WHERE token = ?",
                (refresh_token.token,)
            ) as cursor:
                if not await cursor.fetchone():
                    raise ValueError("Invalid refresh token")

            # SECURITY: Invalidate any old access tokens associated with this refresh token
            # This will automatically happen when we delete the old refresh token due to CASCADE
            await db.execute(
                "DELETE FROM access_tokens WHERE refresh_token = ?",
                (refresh_token.token,)
            )

            # SECURITY: Implement refresh token rotation
            # Create a new refresh token first
            new_refresh_token = f"mcp_refresh_{secrets.token_hex(32)}"
            refresh_token_expiry = int(time.time()) + (90 * 24 * 3600)  # 90 days

            await db.execute(
                """INSERT INTO refresh_tokens (token, client_id, subject, scopes, expires_at, resource)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (new_refresh_token, client.client_id, refresh_token.subject,
                 json.dumps(refresh_token.scopes), refresh_token_expiry, refresh_token.resource)
            )

            # Create a new access token associated with the new refresh token
            new_access_token = f"mcp_{secrets.token_hex(32)}"
            expires_at = int(time.time()) + 3600
            await db.execute(
                """INSERT INTO access_tokens (token, client_id, subject, scopes, expires_at, resource, refresh_token)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (new_access_token, client.client_id, refresh_token.subject,
                 json.dumps(refresh_token.scopes), expires_at, refresh_token.resource, new_refresh_token)
            )

            # Invalidate the old refresh token (and any remaining access tokens via CASCADE)
            await db.execute("DELETE FROM refresh_tokens WHERE token = ?", (refresh_token.token,))

            await db.commit()

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(refresh_token.scopes),
            refresh_token=new_refresh_token,  # Return the NEW refresh token
        )

    async def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            # Remove from access tokens
            await db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))

            # Remove from refresh tokens (CASCADE will delete associated access tokens)
            await db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))

            await db.commit()

def _extract_video_id(video_input: str) -> str:
    video_input = video_input.strip()

    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})',
        r'^([a-zA-Z0-9_-]{11})$'
    ]

    for pattern in patterns:
        match = re.search(pattern, video_input)
        if match:
            return match.group(1)

    raise ValueError(f"Could not extract valid YouTube video ID from: {video_input}")

def _format_segment(entry: dict) -> str:
    """Format a single transcript segment with timestamp."""
    timestamp_seconds = int(entry['start'])
    minutes = timestamp_seconds // 60
    seconds = timestamp_seconds % 60
    return f"[{minutes:02d}:{seconds:02d}] {entry['text']}"

def _handle_transcript_error(e: Exception, video_id: str) -> str:
    if isinstance(e, TranscriptsDisabled):
        return f"Error: Transcripts are disabled for video {video_id}. The video owner has disabled transcript access."
    elif isinstance(e, NoTranscriptFound):
        return f"Error: No transcript found for video {video_id}. Try using youtube_list_available_transcripts to see what's available."
    elif isinstance(e, VideoUnavailable):
        return f"Error: Video {video_id} is unavailable. It may be private, deleted, or the ID is incorrect."
    elif isinstance(e, ValueError):
        return f"Error: {str(e)}"
    else:
        return f"Error: Unexpected error occurred: {type(e).__name__}: {str(e)}"

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

oauth_provider = GoogleOAuthProvider(SERVER_URL)

mcp = FastMCP(
    "youtube_transcript_mcp",
    host="0.0.0.0",
    port=8000,
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(SERVER_URL),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["youtube_transcript"],
            default_scopes=["youtube_transcript"],
        ),
        required_scopes=["youtube_transcript"],
        resource_server_url=None,
    )
)

@mcp.custom_route("/google/callback", methods=["GET"])
async def google_callback_handler(request: Request) -> Response:
    return await oauth_provider.handle_google_callback(request)

@mcp.tool(
    name="youtube_get_transcript",
    annotations={
        "title": "Get YouTube Video Transcript",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def youtube_get_transcript(
    video_input: str,
    cursor: int = 0
) -> str:
    """Get YouTube video transcript. Pass the video URL or ID.

    The output is paginated and will require multiple calls to fetch the whole transcript.

    Args:
        video_input: YouTube URL or video ID
        cursor: Starting segment index for pagination (default: 0)
    """
    try:
        video_id = _extract_video_id(video_input)

        transcript_list = YouTubeTranscriptApi().list(video_id)

        transcript = None
        try:
            transcript = transcript_list.find_manually_created_transcript(['en'])
        except NoTranscriptFound:
            try:
                transcript = transcript_list.find_generated_transcript(['en'])
            except NoTranscriptFound:
                return f"Error: No English transcripts (manual or auto-generated) available for video {video_id}"

        fetched = transcript.fetch()
        transcript_data = fetched.to_raw_data()
        total_segments = len(transcript_data)

        # Validate cursor
        if cursor < 0:
            cursor = 0
        if cursor >= total_segments:
            return f"Error: Cursor {cursor} is beyond the end of transcript (total segments: {total_segments})"

        # Build result by appending segments until we're close to the limit
        remaining_data = transcript_data[cursor:]

        # Reserve space for pagination metadata
        metadata_overhead = 150

        # Start with header
        result_lines = [f"# YouTube Transcript: {video_id}", ""]
        current_size = len("\n".join(result_lines)) + 1  # +1 for final newline

        # Add segments until we're close to the limit
        segments_added = 0
        for entry in remaining_data:
            # Format this segment
            segment_text = _format_segment(entry)
            segment_size = len(segment_text) + 1  # +1 for newline

            # Check if adding this segment would exceed the limit
            if current_size + segment_size + metadata_overhead > CHARACTER_LIMIT:
                # Only stop if we've added at least one segment
                if segments_added > 0:
                    break

            result_lines.append(segment_text)
            current_size += segment_size
            segments_added += 1

        # Build final result
        result = "\n".join(result_lines)

        # Add metadata
        end_index = cursor + segments_added
        has_more = end_index < total_segments

        result += f"\n\n---\n**Pagination Info:**\n"
        result += f"- Showing segments {cursor + 1}-{end_index} of {total_segments}\n"
        result += f"- Has more: {has_more}\n"
        if has_more:
            result += f"- Next cursor: {end_index}\n"

        return result

    except Exception as e:
        return _handle_transcript_error(e, video_input)

@mcp.tool(
    name="youtube_list_available_transcripts",
    annotations={
        "title": "List Available YouTube Transcripts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def youtube_list_available_transcripts(video_input: str) -> str:
    """List available transcripts for a YouTube video.

    Args:
        video_input: YouTube URL or video ID
    """

    try:
        video_id = _extract_video_id(video_input)

        transcript_list = YouTubeTranscriptApi().list(video_id)

        lines = [f"# Available Transcripts for Video: {video_id}", ""]

        manual_transcripts = []
        generated_transcripts = []

        for transcript in transcript_list:
            info = {
                'language': transcript.language,
                'language_code': transcript.language_code,
                'is_generated': transcript.is_generated,
                'is_translatable': transcript.is_translatable
            }

            if transcript.is_generated:
                generated_transcripts.append(info)
            else:
                manual_transcripts.append(info)

        if manual_transcripts:
            lines.append("## Manually Created Transcripts")
            for t in manual_transcripts:
                lines.append(f"- **{t['language']}** (`{t['language_code']}`)")
                if t['is_translatable']:
                    lines.append("  - Can be translated to other languages")
            lines.append("")

        if generated_transcripts:
            lines.append("## Auto-Generated Transcripts")
            for t in generated_transcripts:
                lines.append(f"- **{t['language']}** (`{t['language_code']}`)")
                if t['is_translatable']:
                    lines.append("  - Can be translated to other languages")
            lines.append("")

        if not manual_transcripts and not generated_transcripts:
            return f"No transcripts available for video {video_id}"

        return "\n".join(lines)

    except Exception as e:
        return _handle_transcript_error(e, video_input)

if __name__ == "__main__":
    # Initialize the database before starting the server
    asyncio.run(init_database())
    mcp.run(transport="sse")
