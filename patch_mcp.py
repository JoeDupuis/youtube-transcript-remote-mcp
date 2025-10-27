#!/usr/bin/env python3
"""
Patch the MCP library to support Perplexity OAuth compatibility.

This script modifies the grant_types validation in the MCP server's
registration handler to accept "authorization_code" alone, without
requiring "refresh_token" to also be present.
"""

import sys
from pathlib import Path

def find_mcp_register_file():
    """Find the register.py file in the installed MCP package."""
    # Try common locations
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"

    possible_paths = [
        Path(f"/usr/local/lib/python{python_version}/site-packages/mcp/server/auth/handlers/register.py"),
        Path(f"/usr/lib/python{python_version}/site-packages/mcp/server/auth/handlers/register.py"),
        Path(f"venv/lib/python{python_version}/site-packages/mcp/server/auth/handlers/register.py"),
    ]

    for path in possible_paths:
        if path.exists():
            return path

    raise FileNotFoundError("Could not find MCP register.py file")

def patch_register_file():
    """Apply the patch to register.py"""
    register_file = find_mcp_register_file()

    print(f"Found register.py at: {register_file}")

    # Read the file
    content = register_file.read_text()

    # Check if already patched
    if "Be flexible: allow authorization_code alone or with refresh_token" in content:
        print("File is already patched. Skipping.")
        return

    # Apply the patch
    old_code = '''        if not {"authorization_code", "refresh_token"}.issubset(set(client_metadata.grant_types)):
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description="grant_types must be authorization_code and refresh_token",
                ),
                status_code=400,
            )'''

    new_code = '''        # Be flexible: allow authorization_code alone or with refresh_token
        grant_types_set = set(client_metadata.grant_types)
        if "authorization_code" not in grant_types_set:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description="grant_types must include authorization_code",
                ),
                status_code=400,
            )'''

    if old_code not in content:
        print("ERROR: Could not find the code to patch. MCP library may have changed.")
        sys.exit(1)

    # Replace the code
    patched_content = content.replace(old_code, new_code)

    # Write back
    register_file.write_text(patched_content)

    print("Successfully patched register.py for Perplexity compatibility!")

if __name__ == "__main__":
    try:
        patch_register_file()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
