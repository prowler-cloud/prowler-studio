from pathlib import Path
from typing import Annotated

import typer
from click.exceptions import Exit

from cli.src.utils.config import get_config
from cli.src.views.menus import (
    get_embedding_model_provider,
    get_embedding_model_reference,
)
from cli.src.views.output import display_error, display_success, display_warning
from core.src.rag.vector_store import CheckMetadataVectorStore


def build_check_rag(
    prowler_directory_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the Prowler directory where the checks are stored",
            exists=True,
        ),
    ],
    embedding_model_provider: Annotated[
        str, typer.Option(help="The embedding model provider")
    ] = "",
    embedding_model_reference: Annotated[
        str, typer.Option(help="The specific embedding model to use")
    ] = "",
    embedding_model_api_key: Annotated[
        str,
        typer.Option(envvar="EMBEDDING_MODEL_API_KEY", help="Embedding model API key"),
    ] = "",
    overwrite: Annotated[
        bool, typer.Option(help="Overwrite the RAG dataset if it already exists")
    ] = None,
) -> None:
    """Build RAG dataset

    Args:
        prowler_directory_path: Path to the Prowler directory where the checks are stored
        embedding_model_provider: The model provider to use
        embedding_model_reference: The specific model reference to use
        embedding_model_api_key: Embedding model API key
    Raises:
        FileExistsError: If the RAG dataset already exists in the specified path
    """
    try:
        if CheckMetadataVectorStore.DEFAULT_STORE_DIR.exists():
            if overwrite is None:
                overwrite = typer.confirm(
                    f"RAG dataset already exists in the path: {CheckMetadataVectorStore.DEFAULT_STORE_DIR.resolve()}. Do you want to overwrite it (only new changes will be added)?"
                )
            if not overwrite:
                raise typer.Exit(code=1)

        config = get_config()

        if not embedding_model_provider:
            embedding_model_provider = (
                get_embedding_model_provider()
                if not config.get("models", {}).get("embedding_model_provider")
                else config.get("models", {}).get("embedding_model_provider")
            )
        if not embedding_model_reference:
            embedding_model_reference = (
                get_embedding_model_reference(embedding_model_provider)
                if not config.get("models", {}).get("embedding_model_reference")
                else config.get("models", {}).get("embedding_model_reference")
            )
        CheckMetadataVectorStore(
            embedding_model_provider=embedding_model_provider,
            embedding_model_reference=embedding_model_reference,
            model_api_key=embedding_model_api_key,
        ).build_check_vector_store(
            prowler_directory_path=prowler_directory_path,
            overwrite=True,
        )
        raise typer.Exit(code=0)
    except Exit as e:
        if e.exit_code == 0:
            display_success("RAG dataset built successfully!")
        elif e.exit_code == 1:
            display_warning(
                "RAG dataset process aborted because no overwrite was selected."
            )
    except Exception as e:
        display_error(f"An error occurred while building the RAG dataset: {e}")
        raise typer.Exit(code=1)
