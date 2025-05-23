import os
import re
from pathlib import Path

from prowler_studio.core.workflows.check_creation.utils.check_metadata_model import (
    CheckMetadata,
)

from ..views.output import display_error


def write_check(
    path: Path, code: str, metadata: CheckMetadata, modified_service_code: str = None
):
    """Write the check code and metadata to the specified path.

    Args:
        path: The path to write the check code and metadata.
        code: The check code to write.
        metadata: The metadata of the check to write.
    Raises:
        OSError: If an error occurs while writing the check.
    """
    try:
        check_name = path.name
        os.makedirs(path, exist_ok=True)
        # Write the check code, metadata and __init__.py file
        with open(
            path.joinpath("__init__.py"),
            "w",
        ) as f:
            f.write("")
        with open(
            path.joinpath(f"{check_name}.metadata.json"),
            "w",
        ) as f:
            f.write(metadata.model_dump_json(indent=2))
        with open(
            path.joinpath(f"{check_name}.py"),
            "w",
        ) as f:
            matches = re.findall(r"```(?:python)?\n([\s\S]*?)```", code)
            code_result = "\n".join([m.strip() for m in matches])
            f.write(code_result)

        if modified_service_code:
            with open(
                path.joinpath(f"modified_{check_name.split('_')[0]}_service.py"),
                "w",
            ) as f:
                matches = re.findall(
                    r"```(?:python)?\n([\s\S]*?)```", modified_service_code
                )
                modified_service_code_result = "\n".join([m.strip() for m in matches])
                f.write(modified_service_code_result)
    except OSError as e:
        display_error("ERROR: Unable to create the check.")
        raise e


def write_fixer(path: Path, code: str) -> None:
    """Write the fixer code to the specified path.

    Args:
        path: The path to write the fixer code.
        code: The fixer code to write.
    Raises:
        OSError: If an error occurs while writing the fixer.
    """
    try:
        fixer_name = path.name
        os.makedirs(path, exist_ok=True)
        with open(
            path.joinpath(fixer_name),
            "w",
        ) as f:
            matches = re.findall(r"```(?:python)?\n([\s\S]*?)```", code)
            code_result = "\n".join([m.strip() for m in matches])
            f.write(code_result)
    except OSError as e:
        display_error("ERROR: Unable to create the fixer.")
        raise e
