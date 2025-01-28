import os
from typing import Annotated

import typer

from cli.src.utils.config import get_config
from cli.src.views.menus import (
    get_embedding_model_provider,
    get_embedding_model_reference,
)
from cli.src.views.output import display_error, display_success
from core.src.utils.build_rag_dataset import build_vector_store


def build_check_rag(
    github_token: Annotated[
        str,
        typer.Option(
            envvar="GITHUB_TOKEN",
            help="GitHub token to extract data from Prowler repository. Needed to make more requests to the GitHub API",
        ),
    ],
    rag_path: Annotated[
        str, typer.Argument(help="Path to the indexed data storage")
    ] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "core",
        "indexed_data_db",
    ),
    model_provider: Annotated[
        str, typer.Option(help="The embedding model provider")
    ] = "",
    model_reference: Annotated[
        str, typer.Option(help="The specific embedding model to use")
    ] = "",
    embedding_model_api_key: Annotated[
        str,
        typer.Option(envvar="EMBEDDING_MODEL_API_KEY", help="Embedding model API key"),
    ] = "",
) -> None:
    """Build RAG dataset

    Args:
        github_token: GitHub token to extract data from Prowler repository
        rag_path: Path to the indexed data storage
        model_provider: The model provider to use
        model_reference: The specific model reference to use
        embedding_model_api_key: Embedding model API key
    Raises:
        FileExistsError: If the RAG dataset already exists in the specified path
    """
    try:
        if os.path.exists(rag_path):
            raise FileExistsError(f"RAG dataset already exists in the path: {rag_path}")
        else:
            config = get_config()

            if not model_provider:
                model_provider = (
                    get_embedding_model_provider()
                    if not config.get("models", {}).get("embedding_model_provider")
                    else config.get("models", {}).get("embedding_model_provider")
                )
            if not model_reference:
                model_reference = (
                    get_embedding_model_reference(model_provider)
                    if not config.get("models", {}).get("embedding_model_reference")
                    else config.get("models", {}).get("embedding_model_reference")
                )
            build_vector_store(
                github_token=github_token,
                model_provider=model_provider,
                model_reference=model_reference,
                api_key=embedding_model_api_key,
                vector_store_path=rag_path,
            )
        display_success("RAG dataset built successfully!")
    except Exception as e:
        display_error(f"Error building RAG dataset: {e}")
        typer.Exit(code=1)
