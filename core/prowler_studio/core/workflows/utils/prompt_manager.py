from abc import ABC, abstractmethod
from enum import Enum

from jinja2 import Environment


class AbstractPromptManager(ABC):
    def __init__(self, model_reference: str):
        self._model_reference = model_reference
        self._jinja_env = self._get_jinja_env()

    @abstractmethod
    def get_prompt(self, step: Enum, **kwargs) -> str:
        """Abstract method to get the prompt for a given workflow step.
        Args:
            step : Step for which to load the prompt template.
            model_reference: Reference to the LLM model, for very known models it can be used to load a specific prompt template.
            **kwargs: Additional keyword arguments to be included in the prompt template.

        Returns:
            The formatted prompt.
        """

    @abstractmethod
    def _get_jinja_env(self) -> Environment:
        """Abstract method to get the Jinja2 environment.

        Returns:
            The Jinja2 environment.
        """
