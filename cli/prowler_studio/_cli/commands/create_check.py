import asyncio
import subprocess
from pathlib import Path
from typing import Annotated, Dict, Union

import typer

from prowler_studio.core.rag.vector_store import CheckMetadataVectorStore
from prowler_studio.core.workflows.check_creation.events import CheckCreationInput
from prowler_studio.core.workflows.check_creation.workflow import ChecKreationWorkflow

from ..utils.config import get_config
from ..utils.file_io import write_check
from ..utils.logging import set_app_log_level
from ..views.menus import get_llm_provider, get_llm_reference
from ..views.output import (
    display_error,
    display_markdown,
    display_success,
    display_warning,
)
from ..views.prompts import (
    ask_execute_new_check,
    confirm_overwrite,
    confirm_save_check,
    prompt_user_message,
)


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
        start_event=CheckCreationInput(
            user_query=user_query,
            llm_provider=model_provider,
            llm_reference=model_reference,
            api_key=api_key,
        ),
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
    log_level: Annotated[str, typer.Option(help="Log level to be used")] = "INFO",
    output_directory: Annotated[
        Path,
        typer.Option(
            help="Output directory to save the check, code and metadata will be saved in a directory with the check name. By default is the current directory, in the generated_checks folder."
        ),
    ] = Path.cwd()
    / "generated_checks",
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
            if Path(CheckMetadataVectorStore.DEFAULT_STORE_DIR).exists():
                set_app_log_level(log_level)

                result = asyncio.run(
                    run_check_creation_workflow(
                        user_query=user_query,
                        model_provider=model_provider,
                        model_reference=model_reference,
                        api_key=llm_api_key,
                    )
                )

                if result.status_code == 2:
                    display_error(result.error_message)
                    typer.Exit(code=1)
                elif result.status_code == 1:
                    display_warning(result.user_answer)
                    typer.Exit(code=1)
                elif result.status_code == 0:
                    display_markdown(result.user_answer)

                    # Ask to the user to save the check code and metadata in his local Prowler repository
                    save_check = (
                        confirm_save_check(output_directory.resolve())
                        if not save_check
                        else save_check
                    )

                    if save_check:
                        check_name = result.check_path.split("/")[-1]
                        check_provider = result.check_path.split("/")[2]

                        output_directory = Path(output_directory, check_name).resolve()

                        # Check if the check path exists
                        if output_directory.exists():
                            # If the check path exists, ask the user if he wants to overwrite the check
                            save_check = confirm_overwrite()

                        if save_check:
                            # If the check path does not exist, save the check
                            write_check(
                                path=output_directory,
                                code=result.check_code,
                                metadata=result.check_metadata,
                                modified_service_code=result.service_code,
                            )

                            if (
                                not result.service_code
                                and check_provider == "aws"
                                and ask_execute_new_check()
                            ):
                                prowler_command = [
                                    "prowler",
                                    check_provider,
                                    "--checks-folder",
                                    output_directory.parent,
                                    "-c",
                                    check_name,
                                    "--output-directory",
                                    Path(
                                        output_directory.resolve(), "output"
                                    ).resolve(),
                                    "--verbose",
                                ]

                                formated_command = " \\\n".join(
                                    [f"    {param}" for param in prowler_command]
                                )

                                display_success(
                                    f"Check saved successfully in {output_directory.resolve()}. Now you can run it with Prowler using the command:\n\n{formated_command}"
                                )

                                # Ask the user if he wants to execute the new check
                                try:
                                    execution_status_code = subprocess.run(
                                        prowler_command, check=False
                                    )

                                    if execution_status_code.returncode == 0:
                                        display_success(
                                            "It seems that your cloud is secure!"
                                        )
                                    elif execution_status_code.returncode == 3:
                                        display_warning(
                                            "It seems that your cloud is not secure! My recommendations to remediate the issues are:"
                                        )
                                        display_markdown(result.generic_remediation)
                                except FileNotFoundError:
                                    display_error(
                                        "Prowler command not found. Please ensure Prowler is installed and available in your PATH."
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
