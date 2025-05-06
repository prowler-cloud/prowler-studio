# Prowler Studio CLI

## Overview

The Prowler Studio CLI is a command-line tool for generating security checks for [Prowler](https://github.com/prowler-cloud/prowler) using AI. It supports multiple LLM providers (Gemini and OpenAI), and can be run via Docker or directly from source. The CLI is built on top of the Prowler Studio Core, providing a user-friendly interface for check generation, RAG knowledge base managing and compliance requirements updates.

## Demo Time!

![Prowler Studio CLI](../docs/img/prowler_studio_cli_demo.gif)

---

## Installation & Setup

### Docker
**Requirements:**
- `git`
- `docker`

```bash
git clone git@github.com:prowler-cloud/prowler-studio.git
cd prowler-studio
docker build -f ./cli/Dockerfile -t prowler-studio-cli:latest .
```

Run the CLI:
```bash
docker run --rm -it --env-file .env prowler-studio-cli
```

To persist generated checks:
```bash
docker run --rm -it --env-file .env -v $(pwd)/generated_checks:/home/prowler_studio/prowler_studio/_cli/generated_checks prowler-studio-cli
```

> [!WARNING]
> If you have problems with the permissions of the generated checks folder add write permissions to write in the folder by other users.
> You can do it with the following command: `chmod o+w $(pwd)/generated_checks`.

### From Source
**Requirements:**
- `git`
- `uv` ([installation guide](https://docs.astral.sh/uv/getting-started/installation/))
- Python 3.12+

```bash
git clone git@github.com:prowler-cloud/prowler-studio.git
cd prowler-studio
uv sync
uv tool install -e ./cli/
cp .env.template .env
```

Fill in `.env` with your API keys (see below).

---

## Configuration

The LLM to use can be selected in a interactive way by the CLI, using command especific flags or by editing the `cli/prowler_studio/_cli/config.yaml` file.

An example of the `cli/prowler_studio/_cli/config.yaml` file is the following:
```yaml
models:
  llm_provider: "openai" # or "gemini"
  llm_reference: "gpt-4o" # or "models/gemini-1.5-flash"
  embedding_model_provider: "gemini"
  embedding_model_reference: "text-embedding-004"
```

---

## Environment Variables

- `GOOGLE_API_KEY`: Must be always set, because it is used for the semantic search in the check knowledge base. You can get one for free from [here](https://ai.google.dev/gemini-api/docs/api-key).
- `OPENAI_API_KEY`: LLM provider API key. This is only used in the case that in the check creation you want to use the OpenAI model supported by the Studio. See [Supported LLM Providers and Models](core.md#supported-llm-providers-and-models) for a list of available models.

---

## Supported Platforms
- Linux, macOS (Python 3.12+)

---

## CLI Commands

All commands are implemented as Typer subcommands in `cli/prowler_studio/_cli/commands/`. For help, run:
```bash
prowler-studio --help
```

### `create-check`
Generate a new Prowler check from a natural language prompt.

**Usage:**
```bash
prowler-studio create-check "<your prompt>" [OPTIONS]
```
**Options:**
- `--model-provider TEXT`         The model provider to use (overrides config)
- `--model-reference TEXT`        The specific model reference to use
- `--llm-api-key TEXT`            LLM API key (env: LLM_API_KEY)
- `--embedding-model-api-key TEXT` Embedding model API key (env: EMBEDDING_MODEL_API_KEY)
- `--log-level TEXT`              Log level (default: INFO)
- `--output-directory PATH`       Directory to save the check (default: ./generated_checks)
- `--save-check`                  Save the generated check in the output directory

**References:**
- Uses the [Check Creation Workflow](core.md#workflows) from the core module.
- See also: [CheckMetadataVectorStore](core.md#checkmetadatavectorstore)

### `build-check-rag`
Build or update the RAG (Retrieval-Augmented Generation) dataset from the Prowler codebase.

**Usage:**
```bash
prowler-studio build-check-rag <path-to-prowler-directory> [OPTIONS]
```
**Options:**
- `--embedding-model-provider TEXT`   Embedding model provider
- `--embedding-model-reference TEXT`  Embedding model reference
- `--embedding-model-api-key TEXT`    Embedding model API key
- `--overwrite`                      Overwrite the RAG dataset if it exists

**References:**
- See [RAG and LlamaIndex Integration](core.md#retrieval-augmented-generation-rag-and-llamaindex-integration)

### `update-compliance`
Update compliance requirements using the latest checks and semantic search.

**Usage:**
```bash
prowler-studio update-compliance <compliance.json> [OPTIONS]
```
**Options:**
- `--max-check-number-per-requirement, -m INTEGER`  Max checks per requirement (default: 5)
- `--confidence-threshold, -c FLOAT`                Confidence threshold (default: 0.6)

**References:**
- Uses the [Compliance Updater Workflow](core.md#workflows)

---

## Example Usage
```bash
prowler-studio create-check "Create a new AWS check to ensure EC2 security groups with inbound rules allowing unrestricted ICMP access are not present."
prowler-studio build-check-rag /path/to/prowler
prowler-studio update-compliance --max-check-number-per-requirement 5 --confidence-threshold 0.6 compliance_test.json
```

---

## Extending the CLI

- Add new commands in `cli/prowler_studio/_cli/commands/` as Typer functions.
- Register them in `cli/prowler_studio/_cli/__main__.py`.
- Use utility functions from `cli/prowler_studio/_cli/utils/` for config, file I/O, and logging.
- For output formatting and prompts, see `cli/prowler_studio/_cli/views/`.
- Reference [Typer documentation](https://typer.tiangolo.com/) for advanced CLI patterns.

---

## Troubleshooting & FAQ

- **Config file not found:** Ensure `cli/prowler_studio/_cli/config.yaml` exists and is readable.
- **API key errors:** Set the correct environment variables. See [Environment Variables](#environment-variables).
- **Docker volume issues:** Use absolute paths for `-v` when mounting volumes.

---

## Technical Details & Architecture

- The CLI is built with [Typer](https://typer.tiangolo.com/) and organized by command in `cli/prowler_studio/_cli/commands/`.
- Configuration is loaded from `cli/prowler_studio/_cli/config.yaml` (see [Configuration](#configuration)).
- Utility modules in `cli/prowler_studio/_cli/utils/` handle config, file I/O, and logging.
- Output formatting and user prompts are in `cli/prowler_studio/_cli/views/`.
- The CLI interfaces with the Prowler Studio Core for workflows, RAG, and compliance logic. See [core.md](core.md) for details on:
  - Workflow classes and orchestration
  - RAG dataset and vector store
  - Model/provider abstraction
- The CLI is distributed as a Python package (`prowler-studio-cli`) with an entrypoint defined in `pyproject.toml`.
- The Docker image is defined in `cli/Dockerfile` and uses the CLI as its entrypoint.

---

## Development Guidelines
- Follow PEP8 and use pre-commit hooks (`uv tool install pre-commit && pre-commit install`).
- Extend commands in `cli/prowler_studio/_cli/commands/`.
- Configuration in `cli/prowler_studio/_cli/config.yaml`.
- Tests and further development should be added in future releases.
- For core logic, see [core.md](core.md).
