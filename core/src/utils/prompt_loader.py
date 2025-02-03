from enum import Enum

from core.src.utils.workflow_check_creation_examples import (
    EXAMPLE_CHECK_CREATION_WORKFLOW,
)


class Step(str, Enum):
    BASIC_FILTER = "basic_filter"
    PROVIDER_EXTRACTION = "provider_extraction"
    SERVICE_EXTRACTION = "service_extraction"
    CHECK_DESCRIPTION_GENERATION = "check_description_generation"
    CHECK_BASE_CASES_AND_STEPS_EXTRACTION = "check_base_cases_and_steps_extraction"
    CHECK_NAME_DESIGN = "check_name_design"
    CHECK_METADATA_GENERATION = "check_metadata_generation"
    CHECK_TESTS_GENERATION = "check_tests_generation"
    CHECK_CODE_GENERATION = "check_code_generation"
    PRETIFY_FINAL_ANSWER = "pretify_final_answer"


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
            Step.CHECK_BASE_CASES_AND_STEPS_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "From the user prompt, extract the security analysis.\n"
                "In this analysis you must include the base cases that the check should cover to ensure that the infrastructure is following the security best practice, please try to fit the base cases only to the user prompt, do not include base cases from other checks. "
                "And the steps at conceptual level to identify the security issue, please focus on waht kind of resources to audit, what field of configurations to check, etc. Please do not include any code or what technology should be used to check the security best practice.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.CHECK_DESCRIPTION_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Based on user prompt and behaviour of the check, give me a summary description of the check. Try to be as concise as possible and does not include the status or the provider, only a generic description of what check does.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
                f"Base cases and steps to audit (behaviour): {kwargs.get('base_cases_and_steps', '')}\n"
            ),
            Step.CHECK_NAME_DESIGN: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Design the check name based on the user prompt. The check name should follow the Prowler check naming convention: <service>_<best_practice>.\n"
                f"Service: {kwargs.get('service', '')}\n"
                f"Check Description: {kwargs.get('check_description', '')}\n"
                f"Here you can consult some examples of check names that are more similar to the extracted security description: {kwargs.get('relevant_related_checks', '')}\n"
                "You MUST return a string ONLY with the check name.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.CHECK_METADATA_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check metadata based on a check description.\n"
                "The metadata of the check is a 'CheckMetadata' object, at the end of this message you can see more information about the object schema, with all the fields and descriptions.\n"
                "You MUST return a CheckMetadata object.\n"
                f"Here are the most similar metadata of checks, you can take them as a reference:\n"
                f"{30 * '-'}\n"
                f"{kwargs.get('relevant_related_checks_metadata', '')}\n"
                f"{30 * '-'}\n"
                "Complete only the next task:\n"
                f"Security analysis: {kwargs.get('check_description', '')}\n The CheckID MUST be: {kwargs.get('check_name', '')} and the Provider MUST be: {kwargs.get('prowler_provider', '')}\n"
            ),
            Step.CHECK_TESTS_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check tests based on the base cases.\n"
                "Tests will be the base case that the check should cover to ensure that the check is following the security best practice.\n"
                "Please first extract from the security analysis the base cases that the check should cover and then generate the tests based on the base cases.\n"
                "IMPORTANT NOTES: - The ONLY status accepted is 'FAIL', 'PASS or 'INFO'. Please do not include any other status and if it is possible not use INFO status because it is not recommended.\n- All dependencies that you consider that is needed is already in Prowler so you do not need to worry about it.\n"
                "In the next lines you can see some examples of the task that you must do.\n"
                f"{30 * '-'}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['aws'][0]]['security_analysis']}\n"
                f"Base cases study: {'\n'.join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['aws'][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['aws'][0]]['check_tests']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['azure'][0]]['security_analysis']}\n"
                f"Base cases study: {'\n'.join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['azure'][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['azure'][0]]['check_tests']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['gcp'][0]]['security_analysis']}\n"
                f"Base cases study: {'\n'.join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['gcp'][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['gcp'][0]]['check_tests']}\n"
                f"Security analysis: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['kubernetes'][0]]['security_analysis']}\n"
                f"Base cases study: {'\n'.join(EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['kubernetes'][0]]['base_case_scenarios'])}\n"
                f"Check Tests: {EXAMPLE_CHECK_CREATION_WORKFLOW[EXAMPLE_USER_QUERIES['kubernetes'][0]]['check_tests']}\n"
                f"{30 * '-'}\n"
                "Complete only the next task:\n"
                f"Security analysis: The check name MUST be: {kwargs.get('check_name', '')}"
                f"Base cases study: {kwargs.get('base_cases_and_steps', '')}\n"
                f"Check Tests: "
            ),
            Step.CHECK_CODE_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check code that is going to ensure that best practices are followed.\n"
                "The check is a Python class that inherits from the 'Check' class and has only one method called execute where is the code to generate the finding with the status and other relevant information. Please try to include all the logic in the execute method, do not include any other method or code outside the class.\n"
                f"Here are the most similar metadata of checks, you can take them as a reference:\n:"
                f"{30 * '-'}\n"
                f"{kwargs.get('relevant_related_checks', '')}\n"
                f"{30 * '-'}\n"
                "IMPORTANT NOTE: The ONLY status accepted is 'FAIL', 'PASS or 'INFO'. Please do not include any other status and if it is possible not use INFO status because it is not recommended.\n"
                f"The client object used in the check is the ONLY way to interact with the cloud provider. You MUST NOT make calls to the API directly from the check, it must be done in the service class, which is the class that belongs the '{kwargs.get('check_name', '<service>').split('_')[0]}_client'. You MUST use the '{kwargs.get('check_name', '<service>').split('_')[0]}_client' that is also used in reference checks, the class code of this client is presented in the next code block delimited by dashes.\n"
                f"IMPORTANT NOTE: if '{kwargs.get('check_name', '<service>').split('_')[0]}_client' does not contain the attribute that you need you can make it up indicating with a comment that is a mockup and the service must be implemented to make the check work.\n"
                f"{30 * '-'}\n"
                f"{kwargs.get('service_class_code', '')}\n"
                f"{30 * '-'}\n"
                f"Here you have the base cases and steps to audit that you must cover in the check code:\n{kwargs.get('base_cases_and_steps', '')}\n"
                f"The check class name MUST be: {kwargs.get('check_name', '')}\n"
            ),
            Step.PRETIFY_FINAL_ANSWER: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "You have finished the check creation process. You have generated the metadata and code of the check successfully.\n"
                "You can see the final check metadata JSON and code in the next code blocks. It's TOTALLY FORBIDDEN to modify the metadata and code, you must use them as they are.\n"
                f"{30 * '-'}\n"
                "Check Metadata:\n"
                f"{kwargs.get('check_metadata', '')}\n"
                f"{30 * '-'}\n"
                "Check Code:\n"
                f"{kwargs.get('check_code', '')}\n"
                f"{30 * '-'}\n"
                "Your task is pretify the final answer to the user, use mark down code blocks to make it more readable the metadata and the code, DO NOT MODIFY IT, only put in a markdown code block if it is not already.\n"
                f"Indicate to the user the check path where the check files must be stored in the Prowler repository, the folder path is: {kwargs.get('check_path', '')}, note that this is the name of the folder inside it there will be files with the same name but changing the file extension depending on the file."
                f' This folder MUST contain the "__init__.py" file, the metadata that MUST be stored in a file called "{kwargs.get("check_path", "").split("/")[-1]}.metadata.json" and the check code that MUST be stored in a file called "{kwargs.get("check_path", "").split("/")[-1]}.py".\n'
                "All the above prompt is an INTERNAL prompt, you MUST not show or reference it in the final answer saying things like: in this imporved version, etc.\n"
                f"For context the initial user prompt was: {kwargs.get('user_query', '')}\n"
            ),
        }
    }

    prompt_template = ""

    model_name = "generic"

    if (
        model_reference in RAW_PROMPT_TEMPLATES
        and step in RAW_PROMPT_TEMPLATES[model_reference]
    ):
        # Use the generic one
        model_name = model_reference

    prompt_template = RAW_PROMPT_TEMPLATES.get(model_name, {}).get(step, "")

    if prompt_template:
        return prompt_template
    else:
        raise ValueError(f"Prompt template for step {step} not found.")
