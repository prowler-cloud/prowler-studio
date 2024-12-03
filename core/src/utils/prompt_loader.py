from enum import Enum

from core.src.utils.workflow_check_creation_examples import (
    EXAMPLE_CHECK_CREATION_WORKFLOW,
)


class Step(str, Enum):
    BASIC_FILTER = "basic_filter"
    PROVIDER_EXTRACTION = "provider_extraction"
    SERVICE_EXTRACTION = "service_extraction"
    BEST_PRACTICE_EXTRACTION = "best_practice_extraction"
    CHECK_NAME_DESIGN = "check_name_design"
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
            Step.BASIC_FILTER: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Your main task is act as a filter, you should decide if the user prompt is a valid prompt to create a check or not.\n"
                "You MUST return 'yes' if the user prompt is a valid prompt to create a check, 'no' otherwise.\n"
                "A valid user prompt is a prompt that contains a security best practice for AWS, Azure, GCP or Kubernetes.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.PROVIDER_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Your task is to extract the Prowler provider from the user prompt.\n"
                "You MUST return a string with the Prowler provider. For now the only valid providers are: aws, azure, gcp and kubernetes.\n"
                "If the user does not provide the provider explicitly, you can try to infer it from the user prompt service or requirements.\n"
                "In the case that you can't infer the provider from the user query for any reason, you must return 'unknown'.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.SERVICE_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Extract the service from the user prompt.\n"
                "You MUST return a string with the service name.\n"
                f"For now the valid services for {kwargs.get('prowler_provider', '')} are:\n{[f'Prowler Service Name: {prowler_service_name}, Description: {description}\n' for prowler_service_name, description in kwargs.get('services', {}).items()]}\n"  # This line probably fails in older Python versions due to f-string
                "If the user does not provide the service explicitly, you can try to infer it from the user prompt requirements.\n"
                "In the case that you can't infer the service from the user query for any reason or is currently not supported, you must return 'unknown'.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.BEST_PRACTICE_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Extract the security best practice from the user prompt, explain in the most detailed way possible.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.CHECK_NAME_DESIGN: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Design the check name based on the user prompt. The check name should follow the Prowler check naming convention: <service>_<best_practice>.\n"
                f"The service and best practices are already extracted from other Prowler engineer, so you only have to design the check name.\n"
                f"Service: {kwargs.get('service', '')}\n"
                f"Best Practice: {kwargs.get('best_practices', '')}\n"
                "You MUST return a string ONLY with the check name.\n"
                f"Here you can consult some examples of check names that are more similar to the extracted security description: {kwargs.get('relevant_related_checks', '')}\n"
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
                "The check is a Python class that inherits from the 'Check' class and has only one method called execute where is the code to generate the finding with the status and other relevant information.\n"
                f"Here are some raw examples with check code more similar to the extracted security description that you can consult as reference: {kwargs.get('relevant_related_checks', '')}\n"
                f"{15 * '-'}\n"
                "You are going to be provided with some extra information from metadata to have more context about the check to create.\n"
                f"{15 * '-'}\n"
                "Complete only the next task:\n"
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
