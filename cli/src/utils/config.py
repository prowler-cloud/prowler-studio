import os
from typing import Dict

import yaml

CONFIG_RELATIVE_PATH = os.path.join(
    os.path.dirname(__file__), "../../config/config.yaml"
)


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
