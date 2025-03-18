from enum import Enum


class Step(str, Enum):
    BASIC_FILTER = "basic_filter"
    PROVIDER_EXTRACTION = "provider_extraction"
    SERVICE_EXTRACTION = "service_extraction"
    USER_INPUT_SUMMARY = "user_input_summary"
    CHECK_NAME_DESIGN = "check_name_design"
    AUDIT_STEPS_EXTRACTION = "audit_steps_extraction"
    CHECK_METADATA_GENERATION = "check_metadata_generation"
    CHECK_CODE_GENERATION = "check_code_generation"
    PRETIFY_FINAL_ANSWER = "pretify_final_answer"
    REMEDIATION_GENERATION = "remediation_generation"


def load_prompt_template(step: Step, model_reference: str, **kwargs) -> str:
    """Load the prompt template for the given step.

    Args:
        step (Step): Step for which to load the prompt template.
        model_reference (str): Reference to the LLM model, for very known models it can be used to load a specific prompt template.
        **kwargs: Additional keyword arguments to be included in the prompt template.
    """

    SYSTEM_CONTEXT_PROMPT = """Your name is Prowler Studio and you are a security engineer specialized in cloud security and python developing working in a cloud security tool called Prowler. Mainly you work in all the parts of the proccess of check creation, a check is an automated security control that checks a specific security best practice in a cloud provider service.\n
    A check is composed by two parts: the Python code that using the the proper Python SDK audit for ensure the security best practice are being follwed and the metadata that contains extra information useful for the user like the description, the severity of the check, the risk, the remediation steps, etc.\n
    When a check is executed by Prowler it generates a finding with a status (PASS, FAIL, INFO) that indicates if the security best practice is being followed or not, and other relevant information for the user like the ID of resource affected and a extended status to give more information about the finding.\n"""

    RAW_PROMPT_TEMPLATES = {
        "generic": {
            Step.BASIC_FILTER: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Your main task is act as a filter, you should decide if the user prompt is a valid prompt to create a check or not.\n"
                "You MUST return 'yes' if the user prompt is a valid prompt to create a check, otherwise return in a friendly way why the user prompt is not valid.\n"
                "Valid prompts are:\n"
                f"- Requests that contains a security assesment that can be audited in an automated way for one of the supported providers.\n"
                f"- Modified versions of existing checks that are not already implemented in Prowler.\n"
                "You can only create one check per user prompt, so if the user request for creating more than one check you must return that the user prompt is not valid.\n"
                f"The valid providers are: {', '.join(kwargs.get('valid_providers', {}))}\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.PROVIDER_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Your task is to extract the Prowler provider from the user prompt.\n"
                f"You MUST return a string with the Prowler provider. For now the only valid providers are: {', '.join(kwargs.get('valid_providers', {}))}\n"
                "If the user does not provide the provider explicitly, you can try to infer it from the user prompt service or requirements.\n"
                "In the case that you can't infer the provider from the user query for any reason, you must return 'unknown'.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.SERVICE_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Extract the service from the user prompt.\n"
                "You MUST return a string with the service name.\n"
                f"For now the valid services for {kwargs.get('prowler_provider', '')} are: {', '.join(kwargs.get('services', {}))}.\n"
                "If the user does not provide the service explicitly, you can try to infer it from the user prompt requirements.\n"
                "In the case that you can't infer the service from the user query for any reason or is currently not supported, you must return 'unknown'.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
            ),
            Step.USER_INPUT_SUMMARY: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Summarize the user input analysis for the check creation. In this summary you have to include all the relevant information that can be useful for the check creation process.\n"
                "The summary MUST be shorter or equal than the user prompt.\n"
                f"User prompt: {kwargs.get('user_query', '')}\n"
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
            Step.AUDIT_STEPS_EXTRACTION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Extract the audit steps from the user check summary. You should extact the steps that will be followed in the check progammatically at a high level to successfully audit the proposed request, you don't need to give details about the calls just the high level concepts.\n"
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
                f"Check description: {kwargs.get('check_description', '')}\n The CheckID MUST be: {kwargs.get('check_name', '')} and the Provider MUST be: {kwargs.get('prowler_provider', '')}\n"
            ),
            Step.CHECK_CODE_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                f"INITIAL USER PROMPT CONTEXT: {kwargs.get('user_query', '')}"
                "Generate the Prowler check code that is going to ensure that best practices are followed.\n"
                "The check is a Python class that inherits from the 'Check' class and has only one method called execute where is the code to generate the finding with the status and other relevant information. Please try to include all the logic in the execute method, do not include any other method or code outside the class.\n"
                f"Here are the most similar metadata of checks, you can take them as a reference, or if consider that is so similar you can just copy adapting to the user prompt:\n"
                f"{30 * '-'}\n"
                f"{kwargs.get('relevant_related_checks', '')}\n"
                f"{30 * '-'}\n"
                "IMPORTANT NOTE: The ONLY status accepted is 'FAIL', 'PASS or 'INFO'. Please do not include any other status and if it is possible not use INFO status because it is not recommended.\n"
                f"The client object used in the check is the ONLY way to interact with the cloud provider. You MUST NOT make calls to the API directly from the check, it must be done in the service class, which is the class that belongs the '{kwargs.get('check_name', '<service>').split('_')[0]}_client'. You MUST use the '{kwargs.get('check_name', '<service>').split('_')[0]}_client' that is also used in reference checks, the class code of this client is presented in the next code block delimited by dashes.\n"
                f"IMPORTANT NOTE: if '{kwargs.get('check_name', '<service>').split('_')[0]}_client' does not contain the attribute that you need you can make it up indicating with a comment that is a mockup and the service must be implemented to make the check work. Be carefull with using this approach, it is recommended to use only when it is strictly necessary.\n"
                f"IMPORTANT NOTE: Be careful with using external imported functions from lib as {kwargs.get('check_name', '<service>').split('_')[0]}_client method, usually the client does not have this kind of functions is more common to use extra functions that you can extract from the related checks code.\n"
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
            Step.REMEDIATION_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the remediation steps that the user should follow to fix the security issue.\n"
                "The remediation steps are the steps that the user should follow to fix the security issue that the check is auditing.\n"
                "Please try to be as concise as possible and you MUST add commands that the user should follow to fix the issue.\n"
                "Give the result in Markdown format.\n"
                f"All generated check informtion: {kwargs.get('final_answer', '')}\n"
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
