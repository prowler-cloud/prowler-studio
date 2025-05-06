# Prowler Studio ChatBot (API + UI)

## Overview

The Prowler Studio ChatBot provides a web-based interface and API for generating Prowler checks using AI. It consists of a FastAPI backend and a React-based frontend (powered by [Deep Chat](https://deepchat.dev/)).

## Architecture
- **API (FastAPI):** Handles check generation requests, model interaction, and serves as the backend for the UI.
- **UI (React/Deep Chat):** User-friendly web interface for interacting with the assistant.
- **Dockerized:** Both API and UI can be run together via Docker Compose.

## Demo Time!

![Prowler Studio Chatbot](../docs/img/prowler_studio_chatbot_demo.gif)

---

## Installation & Setup

### Docker (Recommended)
**Requirements:**
- `git`
- `docker`

```bash
git clone git@github.com:prowler-cloud/prowler-studio.git
cd prowler-studio
docker compose build
docker compose up -d
```

Access the UI at http://localhost:80.

### Local Installation
#### API
**Requirements:**
- `git`
- `uv`
- Python 3.12+

```bash
git clone git@github.com:prowler-cloud/prowler-studio.git
cd prowler-studio
uv install --no-dev --extra api
```

Start the API server:
```bash
uv run python -m uvicorn api.prowler_studio._api.main:app --host 0.0.0.0 --port 8000
# or
uv run --no-dev prowler-studio-api
```

#### UI
**Requirements:**
- `npm`

```bash
cd ui
npm install
npm run start
```

Access the UI at [http://localhost:3000](http://localhost:3000).

## Configuration
- Environment variables must be set in the `.env` file:
  - `GOOGLE_API_KEY`: Required for embeddings and Gemini LLM (mandatory). You can get one for free from [here](https://ai.google.dev/gemini-api/docs/api-key).
  - `OPENAI_API_KEY`: Required if using OpenAI models.
  - `EMBEDDING_MODEL_API_KEY`: For RAG dataset management (can use same as GOOGLE_API_KEY).
  - `BASE_API_URL`: API server URL (default: http://studio-api)
  - `API_PORT`: Port for API server (default: 8000)
  - `UI_PORT`: Port for UI server (default: 80)
- The API and UI communicate over HTTP (default ports: 8000 for API, 3000/80 for UI).

## Supported Platforms
- API: Linux, macOS (Python 3.12+)
- UI: Any platform with Node.js/npm

## Main Features
- User-friendly web interface for check creation.
- API endpoints for programmatic access.

### Example Usage
- Type a check creation request in the UI and press Enter.
- Use the API endpoint `/generate-check` (see API docs for details).

## Development Guidelines
- API: Follow PEP8 and use pre-commit hooks.
- UI: Follow React/JS best practices.
- Extend API in `api/prowler_studio/_api/`.
- Extend UI in `ui/src/`.
- Tests and further development should be added in future releases.
