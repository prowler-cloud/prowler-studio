# Prowler Studio Core

## Overview

The core of Prowler Studio provides foundational logic and workflows for generating checks for Prowler. It is designed to be model-agnostic and supports integration with multiple LLM providers and embedding models.

## Architecture

- **Modular Design:** The core is structured into logical modules for workflows, RAG (Retrieval-Augmented Generation), and utility functions.
- **Provider Abstraction:** Supports multiple LLM and embedding model providers (Gemini and OpenAI) via configuration.

## Installation & Setup

**Requirements:**
- Python 3.12+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for dependency management)

**Install as part of the monorepo:**
```bash
uv sync
```

## Configuration

The core is configured via the CLI or API layer. See the respective documentation for details on setting LLM and embedding providers.

## Supported LLM Providers and Models

Prowler Studio Core supports multiple LLM providers and models for check generation and RAG workflows. The currently supported providers and models are:

- **Gemini (Google)**
  - `models/gemini-1.5-flash`
  - `text-embedding-004` (for embeddings)
- **OpenAI**
  - `gpt-4o`
  - `gpt-4o-mini`

## Supported Platforms

- Linux, macOS (Python 3.12+)

## Main Features
- Model-agnostic check generation.
- RAG dataset management, based on Prowler's checks.
- Compliance update workflow.

## Usage
The recommended way to use the core is via the CLI, API, or MCP Server.

---

## Technical Details

### Main Classes

- **Workflow Classes** (`core/prowler_studio/core/workflows/`): Each workflow (e.g., check creation, compliance update) is implemented as a subclass of LlamaIndex's `Workflow`, with steps defined for each stage of the process. Example files:
  - Check Creation Workflow: `core/prowler_studio/core/workflows/check_creation/workflow.py`
  - Compliance Updater Workflow: `core/prowler_studio/core/workflows/compliance_updater/workflow.py`
- **CheckMetadataVectorStore** (`core/prowler_studio/core/rag/vector_store.py`): Manages the vector store, builds and updates the RAG dataset, and provides semantic search capabilities.
- **CheckInventory** (`core/prowler_studio/core/rag/check_inventory.py`): Maintains an up-to-date inventory of all checks, services, and providers, supporting efficient updates and deletions.

### Workflows

- **LlamaIndex Workflow**: All major processes (check creation, compliance update) are implemented as [LlamaIndex Workflows](https://docs.llamaindex.ai/en/stable/module_guides/workflow/), allowing for robust, retryable, and modular orchestration. See the workflow files in `core/prowler_studio/core/workflows/`.
- **Check Creation Workflow**: Guides the user through the process of creating a new check, leveraging the RAG dataset to avoid duplicates and suggest services improvements. See `core/prowler_studio/core/workflows/check_creation/workflow.py`.
- **Compliance Updater Workflow**: Maps compliance requirements to relevant checks using semantic search over the RAG dataset. See `core/prowler_studio/core/workflows/compliance_updater/workflow.py`.

### Retrieval-Augmented Generation (RAG) and LlamaIndex Integration

- **RAG Dataset**: The core uses a RAG approach to enhance check generation and compliance mapping. All Prowler check metadata is indexed and stored in a vector store for semantic search and retrieval.
- **LlamaIndex**: The vector store and workflow orchestration are powered by [LlamaIndex](https://www.llamaindex.ai/). The `CheckMetadataVectorStore` class manages the indexing and retrieval of check metadata using LlamaIndex's `VectorStoreIndex` and document schema. See `core/prowler_studio/core/rag/vector_store.py`.
- **Building the RAG Dataset**: The CLI provides a `build-check-rag` command to build or update the RAG dataset from the Prowler codebase. This process extracts, encodes, and indexes all check metadata for fast semantic retrieval. See CLI command in `cli/prowler_studio/_cli/commands/build_rag.py`.
- **Querying the RAG**: Workflows use the vector store to find related checks, validate new check ideas, and map compliance requirements to existing checks using semantic similarity.

### Extending the Core

- **Adding New Workflows**: To add a new workflow, create a new class in the `core/prowler_studio/core/workflows` directory, subclassing `Workflow` from LlamaIndex, and define your steps using the `@step` decorator.
- **Integrating New Models**: The core supports pluggable LLM and embedding providers. Update the configuration or use the model chooser utilities to add support for new providers.

---

## Development Guidelines
- Follow PEP8 and use pre-commit hooks (`uv tool install pre-commit && pre-commit install`).
- Tests and further development should be added in future releases.
