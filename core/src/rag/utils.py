import json
from pathlib import Path
from typing import Union


def read_file(file_path: Path, json_load: bool = False) -> Union[str, dict]:
    """
    Safely reads file content, returning an empty string or dictionary if the file doesn't exist.

    Args:
        file_path: Path to the file to read.
        json_load: If True, attempts to load the file content as JSON. Defaults to False.

    Returns:
        The content of the file (string or dictionary) or an empty string/dictionary if the file doesn't exist.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If json_load is True and the file content is not valid JSON.
    """
    if file_path.exists():
        with open(file_path, "r") as f:
            content = f.read()
            if json_load:
                try:
                    return json.loads(content)
                except json.JSONDecodeError as e:
                    raise json.JSONDecodeError(
                        f"Invalid JSON in file {file_path}: {e.msg}", e.doc, e.pos
                    ) from e
            else:
                return content
    else:
        raise FileNotFoundError(f"File {file_path} not found.")
