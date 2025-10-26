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

CHARACTER_LIMIT = 25000

class GoogleOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):

    def __init__(self, server_url: str):
        self.server_url = server_url
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
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

        email = self.user_emails.get(authorization_code.code, "unknown")

        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            subject=email,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,
        )

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
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
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise NotImplementedError("Refresh tokens not supported")

    async def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> None:
        if token in self.tokens:
            del self.tokens[token]

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

def _format_transcript_markdown(transcript_data: List[dict], video_id: str, include_timestamps: bool) -> str:
    lines = [f"# YouTube Transcript: {video_id}", ""]

    if include_timestamps:
        for entry in transcript_data:
            timestamp_seconds = int(entry['start'])
            minutes = timestamp_seconds // 60
            seconds = timestamp_seconds % 60
            timestamp = f"[{minutes:02d}:{seconds:02d}]"
            lines.append(f"{timestamp} {entry['text']}")
    else:
        for entry in transcript_data:
            lines.append(entry['text'])

    return "\n".join(lines)

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
async def youtube_get_transcript(video_input: str) -> str:
    """Get YouTube video transcript. Just paste the video URL or ID.

    Args:
        video_input: YouTube URL or video ID
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

        result = _format_transcript_markdown(transcript_data, video_id, True)

        if len(result) > CHARACTER_LIMIT:
            truncated_ratio = CHARACTER_LIMIT / len(result)
            truncated_count = int(len(transcript_data) * truncated_ratio)
            truncated_data = transcript_data[:truncated_count]
            result = _format_transcript_markdown(truncated_data, video_id, True)
            result += f"\n\n⚠️ **Transcript truncated**: Showing {truncated_count}/{len(transcript_data)} segments due to length limits."

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
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
