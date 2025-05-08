from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, UndefinedError

from ...utils.prompt_manager import AbstractPromptManager
from ..enum_steps import FixerCreationWorkflowStep


class FixerCreationPromptManager(AbstractPromptManager):

    def get_prompt(self, step: FixerCreationWorkflowStep, **kwargs) -> str:
        """Returns the prompt for the given step in the fixer creation workflow.

        Args:
            step: The step for which to get the prompt.
            **kwargs: Additional arguments to format the prompt.
        """
        try:
            model_template_folder_name = "generic"

            # TODO: Based on the self._model_reference add here an if statement, if there are any specific prompts for specifics mdoels
            # Example:
            # if self._model_reference == "gpt-4o-mini":
            #     model_template_folder_name = "gpt_4o_mini"

            prompt = self._jinja_env.get_template(
                f"{model_template_folder_name}/{step.value}.jinja"
            ).render(**kwargs)
        except FileNotFoundError:
            raise ValueError(f"Prompt template for step {step.value} not found.")
        except UndefinedError as e:
            raise ValueError(
                f"Undefined variable in prompt template for step {step.value}: {e}"
            )
        except Exception as e:
            raise Exception(f"Error rendering prompt for step {step.value}: {e}")
        return prompt

    def _get_jinja_env(self):
        """Returns the Jinja2 environment for rendering prompts."""
        return Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            undefined=StrictUndefined,
            autoescape=True,
        )
