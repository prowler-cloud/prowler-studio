from enum import Enum

from llama_index.core.prompts import PromptTemplate


class Step(str, Enum):
    INPUT_ANALYSIS = "input_analysis"
    METADATA_GENERATION = "metadata_generation"
    TEST_GENERATION = "test_generation"
    CHECK_CREATION = "check_creation"


def load_prompt_template(step: Step, model_reference: str) -> PromptTemplate:
    """Load the prompt template for the given step.

    Args:
        step (Step): Step for which to load the prompt template.
        model_reference (str): Reference to the LLM model, for very known models it can be used to load a specific prompt template.
    """
    RAW_PROMPT_TEMPLATES = {
        "generic": {
            "input_analysis": (
                "Think step by step. Given an user prompt reason about cloud security concerns, this is the first step for create an automation to detect the security Problem for an open source CSPM called Prowler.\n"
                "The result of this step is a object of the class ResultPromptAnalysis, where contains the security_logic, provider, service, type_resources_to_scan and check_name. For more details, see the next lines.\n"
                "DISCLAIMER: If the next user prompt is not related with cloud security or it is impossible to fill some of the above fields, please return a ResultPromptAnalysis object with 'NONE' str in the fields that are not possible to fill.\n"
                "- security_logic (str): What is the cloud security reasoning behind the user prompt? Try to be as specific and concrete as possible in this field..\n"
                "- provider (str): What is the cloud provider that the user prompt is related to? The available options are: aws, azure, gcp, and kubernetes.\n"
                "- service (str): What is the cloud service that the user prompt is related to?\n"
                "- check_name (str): Design a check name for the user prompt. The check name should be in a snake_case format, and follow the pattern of the following example: 'provider_service_security_reason_summarized'. Try to not include the word 'check' in the check name.\n"
                "\nUser prompt: {user_prompt}\nCheckInformation: "
            )
        }
    }

    prompt_template = ""

    if model_reference in RAW_PROMPT_TEMPLATES:
        pass  # Not specific models supported yet
    else:
        # Use the generic one
        prompt_template = RAW_PROMPT_TEMPLATES.get("generic", {}).get(step, "")

    if prompt_template:
        return PromptTemplate(template=prompt_template)
    else:
        raise ValueError(f"Prompt template for step {step} not found")
