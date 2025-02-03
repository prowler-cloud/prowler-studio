import os
import re

from cli.src.views.output import display_error
from core.src.utils.llm_structured_outputs import CheckMetadata


def write_check(path: str, code: str, metadata: CheckMetadata) -> None:
    """Write the check code and metadata to the specified path.

    Args:
        path: The path to write the check code and metadata.
        code: The check code to write.
        metadata: The metadata of the check to write.
    Raises:
        OSError: If an error occurs while writing the check.
    """
    try:
        check_name = os.path.basename(path)
        os.makedirs(path, exist_ok=True)
        # Write the check code, metadata and __init__.py file
        with open(
            os.path.join(path, "__init__.py"),
            "w",
        ) as f:
            f.write("")
        with open(
            os.path.join(
                path,
                f"{check_name}.metadata.json",
            ),
            "w",
        ) as f:
            f.write(metadata.model_dump_json(indent=2))
        with open(
            os.path.join(
                path,
                f"{check_name}.py",
            ),
            "w",
        ) as f:
            code = re.sub(r"```(?:python)?\n([\s\S]*?)```", r"\1", code)
            f.write(code)
    except OSError as e:
        display_error("ERROR: Unable to create the check.")
        raise e
