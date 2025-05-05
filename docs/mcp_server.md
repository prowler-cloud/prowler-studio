# Prowler Studio MCP Server

## Overview

The Prowler Studio MCP Server enables integration of Prowler Studio's AI-powered check generation into development environments via the Model Context Protocol (MCP). It is designed for seamless IDE integration (e.g., Cursor, VS Code).

## Architecture
- **MCP Protocol Implementation:** Exposes Prowler Studio features over MCP for IDEs and tools.
- **Extensible:** Built on top of the core module.
- **Docker and Local Support:** Can be run as a container or directly from source.

## Setup & Installation

### Docker
**Requirements:**
- `git`
- `docker`

```bash
git clone git@github.com:prowler-cloud/prowler-studio.git
cd prowler-studio
docker build -f ./mcp_server/Dockerfile -t prowler-studio-mcp-server:latest .
```

### Local Installation
**Requirements:**
- `git`
- `uv`
- Python 3.12+

```bash
git clone git@github.com:prowler-cloud/prowler-studio.git
cd prowler-studio
uv sync --no-dev --extra mcp_server
```

## Configuration
- Set `GOOGLE_API_KEY` (required) and `OPENAI_API_KEY` (optional) in your environment or `.env` file.
- Configure your IDE to connect to the MCP server (see below for examples).

## Integration Examples

### Cursor IDE
**With Docker:**
```json
{
  "mcpServers": {
    "prowler-studio": {
      "command": "docker",
      "args": ["run", "--rm", "-e", "OPENAI_API_KEY=your_openai_api_key", "-e", "GOOGLE_API_KEY=your_google_api_key", "-i", "prowler-studio-mcp-server:latest"]
    }
  }
}
```
**With uvx:**
```json
{
  "mcpServers": {
    "prowler-studio": {
      "command": "uvx",
      "args": ["/path/to/prowler_studio/mcp_server/"],
      "env": {
        "OPENAI_API_KEY": "your_openai_api_key",
        "GOOGLE_API_KEY": "your_google_api_key"
      }
    }
  }
}
```

### VS Code
Add to your User Settings (JSON) or `.vscode/mcp.json`:
```json
{
  "mcp": {
    "servers": {
      "prowler-studio": {
        "type": "stdio",
        "command": "docker",
        "args": ["run", "--rm", "-e", "OPENAI_API_KEY=your_openai_api_key", "-e", "GOOGLE_API_KEY=your_google_api_key", "-i", "prowler-studio-mcp-server:latest"]
      }
    }
  }
}
```

## Supported Platforms
- Linux, macOS (Python 3.12+)

## Main Features
- IDE integration for check generation.

## Development Guidelines
- Follow PEP8 and use pre-commit hooks
- Extend in `mcp_server/prowler_studio/mcp_server/`
- Tests and further development should be added in future releases.
