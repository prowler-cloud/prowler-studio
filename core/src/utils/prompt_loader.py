from enum import Enum

from core.src.utils.workflow_check_creation_examples import (
    EXAMPLE_CHECK_CREATION_WORKFLOW,
)


class Step(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    SERVICE_PROVIDER_EXTRACTION = "service_provider_extraction"
    CHECK_METADATA_GENERATION = "check_metadata_generation"
    CHECK_TESTS_GENERATION = "check_tests_generation"
    CHECK_CODE_GENERATION = "check_code_generation"


def load_prompt_template(step: Step, model_reference: str, **kwargs) -> str:
    """Load the prompt template for the given step.

    Args:
        step (Step): Step for which to load the prompt template.
        model_reference (str): Reference to the LLM model, for very known models it can be used to load a specific prompt template.
        **kwargs: Additional keyword arguments to be included in the prompt template.
    """

    SYSTEM_CONTEXT_PROMPT = "You are a security engineer specialized in cloud security and python developing working in a cloud security tool called Prowler. Mainly you work in all the parts of the proccess of check creation, a check is an automated security control that checks a specific security best practice in a cloud provider service.\n A check is composed by three parts: the Python code that checks the security best practice, the metadata that contains extra information like description, recommendations, etc. and the tests that set the base cases that the check should cover to ensure that the check is following the security best practice.\n When a check is executed by Prowler it generates a finding with a status (PASS, FAIL, INFO) that indicates if the security best practice is being followed or not, and other relevant information for the user like the ID of resource affected and a extended status to give more information about the finding.\n"

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
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
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
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
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
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check metadata based on a check description.\n"
                "The metadata of the check is a 'CheckMetadata' object, at the end of this message you can see more information about the object schema, with all the fields and descriptions.\n"
                "You MUST return a CheckMetadata object.\n"
                f"{15 * '-'}\n"
                f"Here are some raw examples with check metadata more similar to the extracted security description that you can consult as reference: {kwargs.get('relevant_related_checks', '')}\n"
                f"{15 * '-'}\n"
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
            Step.CHECK_TESTS_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check tests based on a check description.\n"
                "Tests will be the base case that the check should cover to ensure that the check is following the security best practice.\n"
                "Please first extract from the security analysis the base cases that the check should cover and then generate the tests based on the base cases.\n"
                "In the next lines you can see some examples of the task that you must do. Please, do not copy and paste the examples, you must extract the information from the user prompt.\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['security_analysis']}\n"
                f"Base cases study: {"\n".join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['check_tests']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['security_analysis']}\n"
                f"Base cases study: {"\n".join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['check_tests']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['security_analysis']}\n"
                f"Base cases study: {"\n".join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['check_tests']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['security_analysis']}\n"
                f"Base cases study: {"\n".join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['check_tests']}\n"
                f"{15 * '-'}\n"
                "Complete only the next task:\n"
                f"Security analysis: {kwargs.get('check_description', '')}. The check name MUST be: {kwargs.get('check_name', '')} and the provider MUST be: {kwargs.get('prowler_provider', '')}\n"
                "Base cases study: (This is for internal reasoning, you don't need to complete this field)\n"
                f"Check Tests: "
            ),
            Step.CHECK_CODE_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check code that is going to ensure that best practices are followed.\n"
                f"{15 * '-'}\n"
                "The check is a Python class that inherits from the 'Check' class and has only one method called execute where is the code to generate the finding with the status and other relevant information.\n"
                f"{15 * '-'}\n"
                f"Here are some raw examples with check code more similar to the extracted security description that you can consult as reference: {kwargs.get('relevant_related_checks', '')}\n"
                "You are going to be provided with all the tests cases that the code MUST cover and some extra information from metadata to have more context about the check.\n"
                f"In the next lines you can see some examples of the task that you must do. Please, do not copy and paste the examples, you must extract the information from the user prompt.\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['check_metadata']}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['check_tests']}\n"
                f"Check Code: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["aws"][0]]['check_code']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['check_metadata']}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['check_tests']}\n"
                f"Check Code: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["azure"][0]]['check_code']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['check_metadata']}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['check_tests']}\n"
                f"Check Code: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["gcp"][0]]['check_code']}\n"
                f"Check Metadata: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['check_metadata']}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['check_tests']}\n"
                f"Check Code: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES["kubernetes"][0]]['check_code']}\n"
                f"{15 * '-'}\n"
                "Complete only the next task:\n"
                f"Check Metadata: {kwargs.get('check_metadata', '')}\n"
                f"Check Tests: {kwargs.get('check_tests', '')}\n"
                "Check Code: "
            ),
        }
    }

    prompt_template = ""

    model_name = "generic"

    if model_reference in RAW_PROMPT_TEMPLATES:
        # Use the generic one
        model_name = model_reference

    prompt_template = RAW_PROMPT_TEMPLATES.get(model_name, {}).get(step, "")

    if prompt_template:
        return prompt_template
    else:
        raise ValueError(f"Prompt template for step {step} not found.")
