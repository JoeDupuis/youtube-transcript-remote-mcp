#!/usr/bin/env python3

from typing import Optional, List
import os
import re
import secrets
import time
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

CHARACTER_LIMIT = 10000  # Temporary: reduced for testing pagination

class GoogleOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):

    def __init__(self, server_url: str):
        self.server_url = server_url
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        # Map refresh tokens to their associated access tokens for invalidation
        self.refresh_to_access: dict[str, str] = {}
        self.state_mapping: dict[str, dict] = {}
        self.user_emails: dict[str, str] = {}

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info

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
                redirect_uri=AnyHttpUrl(state_data["redirect_uri"]),
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

        # Create access token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            subject=email,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,
        )

        # Create refresh token (expires in 90 days for security)
        refresh_token_expiry = int(time.time()) + (90 * 24 * 3600)  # 90 days
        self.refresh_tokens[mcp_refresh_token] = RefreshToken(
            token=mcp_refresh_token,
            client_id=client.client_id,
            subject=email,
            scopes=authorization_code.scopes,
            expires_at=refresh_token_expiry,
            resource=authorization_code.resource,
        )

        # Track the mapping for token rotation
        self.refresh_to_access[mcp_refresh_token] = mcp_token

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
            refresh_token=mcp_refresh_token,
        )

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> Optional[RefreshToken]:
        token = self.refresh_tokens.get(refresh_token)
        if not token:
            return None

        # Verify the token belongs to the requesting client
        if token.client_id != client.client_id:
            return None

        # Check if token is expired (if it has an expiration)
        if token.expires_at and token.expires_at < time.time():
            del self.refresh_tokens[refresh_token]
            return None

        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Verify the refresh token is still valid
        if refresh_token.token not in self.refresh_tokens:
            raise ValueError("Invalid refresh token")

        # SECURITY: Invalidate the old access token immediately
        old_access_token = self.refresh_to_access.get(refresh_token.token)
        if old_access_token and old_access_token in self.tokens:
            del self.tokens[old_access_token]

        # Create a new access token
        new_access_token = f"mcp_{secrets.token_hex(32)}"
        self.tokens[new_access_token] = AccessToken(
            token=new_access_token,
            client_id=client.client_id,
            subject=refresh_token.subject,
            scopes=refresh_token.scopes,
            expires_at=int(time.time()) + 3600,
            resource=refresh_token.resource,
        )

        # SECURITY: Implement refresh token rotation
        # Create a new refresh token and invalidate the old one
        new_refresh_token = f"mcp_refresh_{secrets.token_hex(32)}"
        refresh_token_expiry = int(time.time()) + (90 * 24 * 3600)  # 90 days

        self.refresh_tokens[new_refresh_token] = RefreshToken(
            token=new_refresh_token,
            client_id=client.client_id,
            subject=refresh_token.subject,
            scopes=refresh_token.scopes,
            expires_at=refresh_token_expiry,
            resource=refresh_token.resource,
        )

        # Update the mapping to the new tokens
        self.refresh_to_access[new_refresh_token] = new_access_token

        # Invalidate the old refresh token
        del self.refresh_tokens[refresh_token.token]
        if refresh_token.token in self.refresh_to_access:
            del self.refresh_to_access[refresh_token.token]

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(refresh_token.scopes),
            refresh_token=new_refresh_token,  # Return the NEW refresh token
        )

    async def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> None:
        # Remove from access tokens
        if token in self.tokens:
            del self.tokens[token]

        # Remove from refresh tokens and clean up mappings
        if token in self.refresh_tokens:
            del self.refresh_tokens[token]
            if token in self.refresh_to_access:
                del self.refresh_to_access[token]

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
    """Get YouTube video transcript. Just paste the video URL or ID.

    Automatically paginates if transcript exceeds MCP response size limits.

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
    mcp.run(transport="sse")
