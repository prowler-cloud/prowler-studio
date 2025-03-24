import asyncio
import json
import os
import typer 

from cli.src.views.menus import get_llm_provider, get_llm_reference

from core.src.workflow import ComplianceUpdaterWorkflow
from typing import Annotated
from cli.src.views.output import display_markdown, display_error
from cli.src.views.prompts import prompt_enter_compliance_path
from cli.src.utils.config import get_config



async def run_compliance_updater_workflow(
    compliance_data: dict, model_provider: str, model_reference: str, api_key: str
) -> dict:
    """Run the compliance updater workflow asynchronously.
    
    Args:
        compliance_data: The compliance data to be updated.
        model_provider: The provider of the model to be used.
        model_reference: The reference or identifier of the model.
        api_key: The LLM API key for the model provider.
    
    Returns:
        The result of the compliance updater workflow.
    """

    workflow = ComplianceUpdaterWorkflow(timeout=300, verbose=False)
    result = await workflow.run(
        compliance_data=compliance_data,
        model_provider=model_provider,
        model_reference=model_reference,
        api_key=api_key,
        verbose=False,
    )
    return result
    


def update_compliance(
    compliance_path: Annotated[str, typer.Option(help="File path to the compliance json file")] = "",
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
):
    """Update compliance data

    Args:
        compliance_path: File path to the compliance json file
    """
    try:
        compliance_data = {}
        config = get_config()

        if not compliance_path:
            compliance_path = prompt_enter_compliance_path()
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

        with open(compliance_path, "r") as f:
            compliance_data = json.load(f)

        if os.path.exists(compliance_path) and compliance_data != {}:
            result = asyncio.run(
                run_compliance_updater_workflow(
                    compliance_data=compliance_data,
                    model_provider=model_provider,
                    model_reference=model_reference,
                    api_key=llm_api_key,
                )
            )

            # Write the updated compliance data to the file
            with open(compliance_path, "w") as f:
                json.dump(result, f, indent=4)
    
            display_markdown("Compliance data updated successfully. :white_check_mark:")

        else:
            display_error(f"Compliance file not found at {compliance_path}")
            typer.Exit(code=1)

    except Exception as e:
        display_error(str(e))
        typer.Exit(code=1)
    