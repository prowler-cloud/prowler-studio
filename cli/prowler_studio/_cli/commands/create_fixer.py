import asyncio
import re
from pathlib import Path
from typing import Annotated

import typer

from prowler_studio.core.rag.vector_store import CheckMetadataVectorStore
from prowler_studio.core.workflows.fixer_creation.events import FixerCreationInput
from prowler_studio.core.workflows.fixer_creation.workflow import FixerCreationWorkflow

from ..utils.config import get_config
from ..utils.file_io import write_fixer
from ..utils.logging import set_app_log_level
from ..views.menus import get_llm_provider, get_llm_reference
from ..views.output import (
    display_error,
    display_markdown,
    display_success,
    display_warning,
)
from ..views.prompts import confirm_overwrite, confirm_save_check, prompt_user_message


async def run_fixer_creation_workflow(
    prowler_provider: str,
    check_id: str,
    model_provider: str,
    model_reference: str,
    api_key: str,
):
    """Run the fixer creation workflow synchronously."""
    workflow = FixerCreationWorkflow(timeout=300, verbose=False)
    return await workflow.run(
        start_event=FixerCreationInput(
            prowler_provider=prowler_provider,
            check_id=check_id,
            llm_provider=model_provider,
            llm_reference=model_reference,
            api_key=api_key,
        )
    )


def create_new_fixer(
    prowler_provider: Annotated[
        str, typer.Option(help="Prowler provider (For now only aws is supported)")
    ] = "aws",
    check_id: Annotated[
        str, typer.Argument(help="Check ID to which the fixer will be added")
    ] = "",
    model_provider: Annotated[
        str,
        typer.Option(help="The model provider to use"),
    ] = "",
    model_reference: Annotated[
        str, typer.Option(help="The specific model reference to use")
    ] = "",
    llm_api_key: Annotated[
        str, typer.Option(envvar="LLM_API_KEY", help="LLM API key")
    ] = "",
    log_level: Annotated[str, typer.Option(help="Log level to be used")] = "INFO",
    output_directory: Annotated[
        Path,
        typer.Option(
            help="Output directory to save the fixer. By default is the current directory, in the generated_fixers folder."
        ),
    ] = Path.cwd()
    / "generated_fixers",
    save_fixer: Annotated[
        bool, typer.Option(help="Save the fixer in the output directory")
    ] = False,
) -> None:
    """Create a new fixer for a given check.

    Args:
        prowler_provider: The provider of the Prowler check.
        check_id: The ID of the Prowler check.
        model_provider: The provider of the LLM.
        model_reference: The reference of the LLM.
        api_key: The API key of the LLM.
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
        if not check_id:
            check_id = prompt_user_message(
                "\n[bold]Enter the check ID for which you want to create a fixer :robot:[/bold]\n╰┈➤"
            )

        check_id = check_id.replace("\n", "").strip()

        if check_id:
            # Ensure that check ID follows the format <service_name>_<check_name>. Use regex to validate the format
            if not re.match(r"^[a-zA-Z0-9_]+$", check_id):
                raise ValueError(
                    "You must introduce a valid check ID format: <service_name>_<check_name_separated_by_underscores>"
                )

            # Check if the check exists in the inventory
            service_name = check_id.split("_")[0]
            inventory = CheckMetadataVectorStore().check_inventory
            available_services = inventory.get_available_services_in_provider(
                prowler_provider
            )
            if service_name not in available_services:
                display_error(
                    f"Service '{service_name}' not found in {prowler_provider}."
                )
                typer.Exit(code=1)
            available_checks = inventory.get_available_checks_in_service(
                prowler_provider, service_name
            )
            if check_id not in available_checks:
                raise ValueError(
                    f"Check ID {check_id} not found in service {service_name} in {prowler_provider}."
                )

            if Path(CheckMetadataVectorStore.DEFAULT_STORE_DIR).exists():
                set_app_log_level(log_level)

                result = asyncio.run(
                    run_fixer_creation_workflow(
                        prowler_provider=prowler_provider,
                        check_id=check_id,
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

                    # Ask to the user to save the fixer code in their local Prowler repository
                    save_fixer = (
                        confirm_save_check(output_directory.resolve())
                        if not save_fixer
                        else save_fixer
                    )

                    if save_fixer:
                        fixer_file = Path(
                            output_directory, Path(result.fixer_path).name
                        ).resolve()
                        if fixer_file.exists():
                            save_fixer = confirm_overwrite()
                        if save_fixer:
                            write_fixer(fixer_file, result.fixer_code)
                            display_success(
                                f"Fixer saved successfully in {fixer_file}."
                            )
                        else:
                            display_warning("Fixer not saved.")
            else:
                raise FileNotFoundError(
                    "RAG dataset not found, you can build it using `build_check_rag` command"
                )
        else:
            raise ValueError("Check ID can't be empty")
    except Exception as e:
        display_error(f"ERROR :cross_mark:: {e}")
        typer.Exit(code=1)
