import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from prowler_studio.core.workflows.compliance_updater.workflow import (
    ComplianceUpdaterWorkflow,
)

from ..views.output import display_error, display_success
from ..views.prompts import prompt_enter_compliance_path


async def run_compliance_updater_workflow(
    compliance_data: dict,
    max_check_number_per_requirement: int,
    confidence_threshold: float,
) -> dict:
    """Run the compliance updater workflow asynchronously.

    Args:
        compliance_data: The compliance data to be updated.
        max_check_number_per_requirement: Maximum number of checks to be added per compliance requirement.
        confidence_threshold: Confidence threshold for the compliance requirements.

    Returns:
        The result of the compliance updater workflow.
    """

    workflow = ComplianceUpdaterWorkflow(timeout=300, verbose=False)
    result = await workflow.run(
        compliance_data=compliance_data,
        max_check_number_per_requirement=max_check_number_per_requirement,
        confidence_threshold=confidence_threshold,
        verbose=False,
    )
    return result


def update_compliance(
    compliance_path: Annotated[
        Path, typer.Argument(help="File path to the compliance json file")
    ] = None,
    max_check_number_per_requirement: Annotated[
        int,
        typer.Option(
            "--max-check-number-per-requirement",
            "-m",
            help="Maximum number of checks to be added to the compliance requirements",
        ),
    ] = 5,
    confidence_threshold: Annotated[
        float,
        typer.Option(
            "--confidence-threshold",
            "-c",
            help="Confidence threshold for the compliance requirements",
        ),
    ] = 0.6,
):
    """Update compliance data

    Args:
        compliance_path: File path to the compliance json file
    """
    try:
        compliance_data = {}

        if compliance_path is None:
            compliance_path = prompt_enter_compliance_path()

        with open(compliance_path, "r") as f:
            compliance_data = json.load(f)

        result = asyncio.run(
            run_compliance_updater_workflow(
                compliance_data=compliance_data,
                max_check_number_per_requirement=max_check_number_per_requirement,
                confidence_threshold=confidence_threshold,
            )
        )

        if isinstance(result, dict):
            # Write the updated compliance data to the file
            with open(compliance_path, "w") as f:
                json.dump(result, f, indent=4)

            display_success("Compliance data updated successfully.")
        else:
            display_error("Failed to update compliance data.")
            typer.Exit(code=1)

    except json.JSONDecodeError:
        display_error(f"Invalid JSON file at {compliance_path}")
        typer.Exit(code=1)
    except Exception as e:
        display_error(str(e))
        typer.Exit(code=1)
