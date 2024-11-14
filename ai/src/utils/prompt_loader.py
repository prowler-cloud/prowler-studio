from enum import Enum

from ai.src.utils.workflow_check_creation_examples import (
    EXAMPLE_CHECK_CREATION_WORKFLOW,
)


class Step(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    SERVICE_PROVIDER_EXTRACTION = "service_provider_extraction"
    CHECK_METADATA_GENERATION = "check_metadata_generation"
    CHKEC_TESTS_GENERATION = "check_tests_generation"
    CHECK_CODE_GENERATION = "check_code_generation"


SYSTEM_CONTEXT_PROMPT = "You are a security engineer specialized in cloud security and python developing working in a cloud security tool called Prowler."


def load_prompt_template(step: Step, model_reference: str, **kwargs) -> str:
    """Load the prompt template for the given step.

    Args:
        step (Step): Step for which to load the prompt template.
        model_reference (str): Reference to the LLM model, for very known models it can be used to load a specific prompt template.
        **kwargs: Additional keyword arguments to be included in the prompt template.
    """

    EXAMPLE_USER_QUERIES = {
        "aws": ["make a check to ensure that the S3 bucket is not public."],
        "azure": ["how can I ensure that my Entra policy is secure?"],
        "gcp": [
            "create a check to ensure BigQuery datasets are encrypted with Customer-Managed Keys (CMKs)."
        ],
        "kubernetes": [
            "create a check to ensure that in my k8s cluster the secrets are not stored in the environment variables."
        ],
    }

    RAW_PROMPT_TEMPLATES = {
        "generic": {
            Step.SECURITY_ANALYSIS: (
                "Extract the cloud security reasoning and steps behind the user prompt, think step by step how the security comprobation could be done.\n"
                "In the next lines you can see some examples of the task that you must do. Please, do not copy and paste the examples, you must extract the information from the user prompt.\n"
                f"User prompt: {EXAMPLE_USER_QUERIES["aws"][0]}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['security_analysis']}\n"
                f"User prompt: {EXAMPLE_USER_QUERIES["azure"][0]}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['security_analysis']}\n"
                f"User prompt: {EXAMPLE_USER_QUERIES["gcp"][0]}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['security_analysis']}\n"
                f"User prompt: {EXAMPLE_USER_QUERIES["kubernetes"][0]}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['security_analysis']}\n"
                f"{15 * '-'}\n"
                "Complete only the next task:\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
                "Security analysis: "
            ),
            Step.SERVICE_PROVIDER_EXTRACTION: (
                "Extract the service provider and service information from the user prompt.\n"
                "You MUST return a CheckBasicInformation object, ONLY one string per field.\n"
                "You can query the security reasoning extracted from other Prowler engineer to help you to extract the service provider and service information. With this information you can design a check name, it should follow the Prowler check naming convention: service_check_description.\n"
                f"Context: {kwargs.get('security_reasoning', '')}\n"
                "In the next lines you can see some examples of the task that you must do. Please, do not copy and paste the examples, you must extract the information from the user prompt.\n"
                f"User prompt: {EXAMPLE_USER_QUERIES['aws'][0]}\n"
                f"prowler_provider: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['aws'][0]]['prowler_provider']}\n"
                f"service: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['aws'][0]]['service']}\n"
                f"check_name: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['aws'][0]]['check_name']}\n"
                f"User prompt: {EXAMPLE_USER_QUERIES['azure'][0]}\n"
                f"prowler_provider: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['azure'][0]]['prowler_provider']}\n"
                f"service: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['azure'][0]]['service']}\n"
                f"check_name: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['azure'][0]]['check_name']}\n"
                f"User prompt: {EXAMPLE_USER_QUERIES['gcp'][0]}\n"
                f"prowler_provider: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['gcp'][0]]['prowler_provider']}\n"
                f"service: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['gcp'][0]]['service']}\n"
                f"check_name: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['gcp'][0]]['check_name']}\n"
                f"User prompt: {EXAMPLE_USER_QUERIES['kubernetes'][0]}\n"
                f"prowler_provider: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['kubernetes'][0]]['prowler_provider']}\n"
                f"service: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['kubernetes'][0]]['service']}\n"
                f"check_name: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['kubernetes'][0]]['check_name']}\n"
                f"{15 * '-'}\n"
                "Complete only the next task:\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.CHECK_METADATA_GENERATION: (
                "Generate the Prowler check metadata based on a check description.\n"
                "A Prowler check is a Python script that checks a specific security best practice in a cloud provider service. The metadata of the check is a 'CheckMetadata' object that contains extra the information about the check.\n"
                "You MUST return a CheckMetadata object.\n"
                "In the next lines you can see some examples of the task that you must do. Please, do not copy and paste the examples, you must extract the information from the user prompt.\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['security_analysis']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['check_metadata']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['security_analysis']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['check_metadata']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['security_analysis']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['check_metadata']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['security_analysis']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['check_metadata']}\n"
                f"{15 * '-'}\n"
                "Complete only the next task:\n"
                f"Security analysis: {kwargs.get('check_description', '')}\n The CheckID MUST be: {kwargs.get('check_name', '')} and the Provider MUST be: {kwargs.get('prowler_provider', '')}\n"
                "Check Metadata: "
            ),
        }
    }

    prompt_template = ""

    if model_reference not in RAW_PROMPT_TEMPLATES:
        # Use the generic one
        prompt_template = RAW_PROMPT_TEMPLATES.get("generic", {}).get(step, "")

    if prompt_template:
        return prompt_template
    else:
        raise ValueError(f"Prompt template for step {step} not found.")
