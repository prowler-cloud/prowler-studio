from pathlib import Path
from typing import Dict

import yaml

CONFIG_RELATIVE_PATH = Path(__file__).parents[1] / "config.yaml"


def get_config() -> Dict:
    """Get the configuration from the yaml configuration file."""

    try:
        with open(CONFIG_RELATIVE_PATH, "r") as file:
            config = yaml.safe_load(file)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Configuration file not found at {CONFIG_RELATIVE_PATH}"
        )

    return config
