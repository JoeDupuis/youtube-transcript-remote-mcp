FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Apply Perplexity OAuth compatibility patch to MCP library
COPY patch_mcp.py .
RUN python patch_mcp.py

COPY youtube_transcript_mcp.py .

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "youtube_transcript_mcp.py"]
