import asyncio
import os
from typing import Annotated, Dict, Union

import typer

from cli.src.utils.config import get_config
from cli.src.utils.file_io import is_prowler_repo, write_check
from cli.src.utils.logging import set_app_log_level
from cli.src.views.menus import get_llm_provider, get_llm_reference
from cli.src.views.output import (
    display_error,
    display_markdown,
    display_success,
    display_warning,
)
from cli.src.views.prompts import (
    ask_prowler_path,
    confirm_overwrite,
    confirm_save_check,
    prompt_user_message,
)
from core.src.workflow import ChecKreationWorkflow


async def run_check_creation_workflow(
    user_query: str, model_provider: str, model_reference: str, api_key: str
) -> Union[Dict, str]:
    """Run the check creation workflow asynchronously.

    Args:
        user_query: The query provided by the user.
        model_provider: The provider of the model to be used.
        model_reference: The reference or identifier of the model.
        api_key: The LLM API key for the model provider.

    Returns:
        The result of the check creation workflow.
    """
    workflow = ChecKreationWorkflow(timeout=60, verbose=False)
    result = await workflow.run(
        user_query=user_query,
        model_provider=model_provider,
        model_reference=model_reference,
        api_key=api_key,
        verbose=False,
    )
    return result


def create_new_check(
    user_query: Annotated[str, typer.Argument(help="User query")] = "",
    model_provider: Annotated[
        str,
        typer.Option(help="The model provider to use"),
    ] = "",
    model_reference: Annotated[
        str, typer.Option(help="The specific model reference to use")
    ] = "",
    llm_api_key: Annotated[
        str, typer.Option(envvar="LLM_API_KEY", help="LLM API key")
    ] = "",  # Is optional because in a future it can support local models that does not need an API key
    embedding_model_api_key: Annotated[
        str,
        typer.Option(envvar="EMBEDDING_MODEL_API_KEY", help="Embedding model API key"),
    ] = "",  # TODO: review this because in a future it should support different keys for embedding models and LLM models
    rag_path: Annotated[
        str, typer.Option(help="Path to the indexed data storage", exists=True)
    ] = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "../../../",
        "core",
        "indexed_data_db",
    ),
    log_level: Annotated[str, typer.Option(help="Log level to be used")] = "INFO",
) -> None:
    """Create a new check

    Args:
        user_query: User query
        model_provider: The model provider to use
        model_reference: The specific model reference to use
        llm_api_key: LLM API key
        embedding_model_api_key: Embedding model API key
        rag_path: Path to the indexed data storage
        log_level: Log level to be used
    """
    try:
        config = get_config()

        if not model_provider:
            model_provider = (
                get_llm_provider()
                if not config.get("models", {}).get("llm_provider")
                else config.get("models", {}).get("llm_provider")
            )
        if not model_reference:
            model_reference = (
                get_llm_reference(model_provider)
                if not config.get("models", {}).get("llm_reference")
                else config.get("models", {}).get("llm_reference")
            )
        if not user_query:
            user_query = prompt_user_message()

        if user_query:
            if os.path.exists(rag_path):
                set_app_log_level(log_level)

                result = asyncio.run(
                    run_check_creation_workflow(
                        user_query=user_query,
                        model_provider=model_provider,
                        model_reference=model_reference,
                        api_key=llm_api_key,
                    )
                )

                if isinstance(result, str):
                    display_warning(result)
                else:
                    display_markdown(result["answer"])

                    # Ask to the user to save the check code and metadata in his local Prowler repository

                    save_check = confirm_save_check()

                    if save_check:
                        prowler_path = (
                            ask_prowler_path()
                            if not config.get("prowler_path", None)
                            else config.get("prowler_path")
                        )
                        # Ensure if the path exists
                        if os.path.exists(prowler_path) and is_prowler_repo(
                            prowler_path
                        ):
                            # Calculate the check path with the user path and the check path from the result
                            check_path = os.path.join(
                                prowler_path, result["check_path"]
                            )
                            # Check if the check path exists
                            if os.path.exists(check_path):
                                # If the check path exists, ask the user if he wants to overwrite the check
                                overwrite_check = confirm_overwrite(check_path)
                                if overwrite_check:
                                    # Make a folder with the check path
                                    write_check(
                                        path=check_path,
                                        code=result["code"],
                                        metadata=result["metadata"],
                                    )
                                    display_success(
                                        f"Check saved successfully in {check_path}."
                                    )
                                else:
                                    display_warning("The check was not saved.")
                            else:
                                # If the check path does not exist, save the check
                                write_check(
                                    path=check_path,
                                    code=result["code"],
                                    metadata=result["metadata"],
                                )
                                display_success(
                                    f"Check saved successfully in {check_path}."
                                )
                        else:
                            raise FileNotFoundError(
                                f"Invalid Prowler repository path: {prowler_path}"
                            )
            else:
                raise FileNotFoundError(
                    "RAG dataset not found, you can build it using `build_check_rag` command"
                )
        else:
            raise ValueError("User query can't be empty")
    except Exception as e:
        display_error(f"ERROR :cross_mark:: {e}")
        typer.Exit(code=1)
