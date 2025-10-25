#!/usr/bin/env python3

from typing import Optional, List
from enum import Enum
import os
import re
import json
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, ConfigDict
from mcp.server.fastmcp import FastMCP, Context
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import (
    TranscriptsDisabled,
    NoTranscriptFound,
    VideoUnavailable
)
from google.oauth2 import id_token
from google.auth.transport import requests
import httpx

load_dotenv()

mcp = FastMCP("youtube_transcript_mcp")

AUTHORIZED_EMAILS = os.getenv("AUTHORIZED_EMAILS", "").split(",")
AUTHORIZED_EMAILS = [email.strip() for email in AUTHORIZED_EMAILS if email.strip()]
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CHARACTER_LIMIT = 25000

def _validate_user_authorization(email: str) -> bool:
    if not AUTHORIZED_EMAILS:
        raise ValueError("No authorized emails configured. Set AUTHORIZED_EMAILS environment variable.")
    if not email:
        return False
    return email.lower() in [auth_email.lower() for auth_email in AUTHORIZED_EMAILS]

def _verify_google_token(token: str) -> Optional[str]:
    try:
        if not GOOGLE_CLIENT_ID:
            raise ValueError("GOOGLE_CLIENT_ID not configured")
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        return idinfo.get('email')
    except Exception as e:
        return None

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

class GetTranscriptInput(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True
    )

    video_input: str = Field(
        ...,
        description="YouTube video ID or URL",
        min_length=11
    )

    @field_validator('video_input')
    @classmethod
    def validate_video_input(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Video input cannot be empty")
        return v.strip()

class ListTranscriptsInput(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True
    )

    video_input: str = Field(
        ...,
        description="YouTube video ID or URL",
        min_length=11
    )

    @field_validator('video_input')
    @classmethod
    def validate_video_input(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Video input cannot be empty")
        return v.strip()

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
    mcp.run(transport="sse")
