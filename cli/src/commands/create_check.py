import asyncio
import os
from pathlib import Path
from typing import Annotated, Dict, Union

import typer

from cli.src.utils.config import get_config
from cli.src.utils.file_io import write_check
from cli.src.utils.logging import set_app_log_level
from cli.src.views.menus import get_llm_provider, get_llm_reference
from cli.src.views.output import (
    display_error,
    display_markdown,
    display_success,
    display_warning,
)
from cli.src.views.prompts import (
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
    workflow = ChecKreationWorkflow(timeout=300, verbose=False)
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
    output_directory: Annotated[
        Path,
        typer.Option(
            help="Output directory to save the check, code and metadata will be saved in a directory with the check name. By default is the root of the project, in the generated_checks folder."
        ),
    ] = Path(
        os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "../../../generated_checks"
        )
    ),
    save_check: Annotated[
        bool, typer.Option(help="Save the check in the output directory")
    ] = False,
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

                    save_check = confirm_save_check() if not save_check else save_check

                    if save_check:
                        output_directory = Path(
                            output_directory, result["check_path"].split("/")[-1]
                        )

                        # Check if the check path exists
                        if output_directory.exists():
                            # If the check path exists, ask the user if he wants to overwrite the check
                            save_check = confirm_overwrite()

                        if save_check:
                            # If the check path does not exist, save the check
                            write_check(
                                path=output_directory,
                                code=result["code"],
                                metadata=result["metadata"],
                            )
                            display_success(
                                f"Check saved successfully in {output_directory.resolve()}. Now you can run it with Prowler using the command:\nprowler {result['check_path'].split('/')[2]} --checks-folder {output_directory.parent.resolve()} -c {result['check_path'].split('/')[-1]}"
                            )
                        else:
                            display_warning("Check not saved.")
            else:
                raise FileNotFoundError(
                    "RAG dataset not found, you can build it using `build_check_rag` command"
                )
        else:
            raise ValueError("User query can't be empty")
    except Exception as e:
        display_error(f"ERROR :cross_mark:: {e}")
        typer.Exit(code=1)
