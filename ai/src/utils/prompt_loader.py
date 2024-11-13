from enum import Enum


class Step(str, Enum):
    SECURITY_ANALYSIS = "security_analysis"
    SERVICE_PROVIDER_EXTRACTION = "service_provider_extraction"
    METADATA_GENERATION = "metadata_generation"
    TEST_GENERATION = "test_generation"
    CHECK_CREATION = "check_creation"


SYSTEM_CONTEXT_PROMPT = "You are a security engineer specialized in cloud security and python developing working in a cloud security tool called Prowler."


def load_prompt_template(step: Step, model_reference: str, **kwargs) -> str:
    """Load the prompt template for the given step.

    Args:
        step (Step): Step for which to load the prompt template.
        model_reference (str): Reference to the LLM model, for very known models it can be used to load a specific prompt template.
        **kwargs: Additional keyword arguments to be included in the prompt template.
    """

    RAW_PROMPT_TEMPLATES = {
        "generic": {
            Step.SECURITY_ANALYSIS: (
                "Your task is to analyze the user prompt and detect if is related to cloud security. If it is related, you must extract the cloud security reasoning and steps behind the user prompt, think step by step how the security comprobation could be done.\n"
                "In the case that the user prompt is not related to cloud security or does not provide enought context, you ONLY MUST return 'NONE'.\n"
                "User prompt: make a check to ensure that the S3 bucket is not public.\n"
                "User prompt analysis:\n"
                "The requested prompt is related to cloud security, specifically with AWS because S3 is an AWS for storage. This is a common security best practice to avoid unauthorized access to the bucket content.\nTo do this check you must verify at 4 levels: - Account level: verify that 'Block Public Access' is enabled for the account settings. - Bucket access permissions: verify each bucket has 'Block pulic access through ACLs' and 'Block public access through bucket policies' enabled. - Access control list (ACL): verify that the bucket does not have an ACL with 'AllUsers' or 'Authenticated Users' with 'List' or 'Write' permissions. - Bucket policy: verify that the bucket does not have a bucket policy that allows public access.\n"
                "User prompt: what is the first day of the week?\n"
                "User prompt analysis:\nNONE\n"
                "User prompt: how can I ensure that my Entra policy is secure?\n"
                "User prompt analysis: "
                "The requested prompt is related to cloud security, specifically with Azure because Entra is the Microsoft product for identity and access management. This is a common security best practice to ensure that the Entra policy is secure to avoid unauthorized access to the resources.\nTo do this check at least you must verify that the Security Defaults are enabled\n"
                "User prompt: what is the best way to reduce the costs of my AKS cluster?\n"
                "User prompt analysis:\nNONE\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
                "User prompt analysis:\n"
            ),
            Step.SERVICE_PROVIDER_EXTRACTION: (
                "Your task is to extract the service provider and service information from the user prompt.\n"
                "You MUST return a CheckBasicInformation object, ONLY one string per field.\n"
                "You can query the security reasoning extracted from other Prowler engineer to help you to extract the service provider and service information. With this information you can design a check name, it should follow the Prowler check naming convention: service_check_description.\n"
                f"Context: {kwargs.get('security_reasoning', '')}\n"
                "In the next lines you can see some examples of the task that you must do. Please, do not copy and paste the examples, you must extract the information from the user prompt.\n"
                "User prompt: make a check to ensure that the S3 bucket is not public.\n"
                "User prompt analysis:\n"
                "prowler_provider: aws\n"
                "service: s3\n"
                "check_name: s3_bucket_not_public_accesible\n"
                "User prompt: how can I ensure that my Entra policy is secure?\n"
                "User prompt analysis:\n"
                "prowler_provider: azure\n"
                "service: entra\n"
                "check_name: entra_security_defaults_enabled\n"
                "User prompt: create a check to ensure BigQuery datasets are encrypted with Customer-Managed Keys (CMKs).\n"
                "prowler_provider: gcp\n"
                "service: bigquery\n"
                "check_name: bigquery_dataset_cmk_encryption\n"
                "User prompt: create a check to ensure that in my k8s cluster the secrets are not stored in the enviroment variables.\n"
                "prowler_provider: kubernetes\n"
                "service: core\n"
                "check_name: core_no_secrets_envs\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
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
