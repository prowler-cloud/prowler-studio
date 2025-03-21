from enum import Enum


class Step(str, Enum):
    BASIC_FILTER = "basic_filter"
    PROVIDER_EXTRACTION = "provider_extraction"
    SERVICE_EXTRACTION = "service_extraction"
    USER_INPUT_SUMMARY = "user_input_summary"
    CHECK_NAME_DESIGN = "check_name_design"
    AUDIT_STEPS_EXTRACTION = "audit_steps_extraction"
    CHECK_METADATA_GENERATION = "check_metadata_generation"
    IS_SERVICE_COMPLETE = "is_service_complete"
    IDENTIFY_NEEDED_CALLS_ATTRIBUTES = "identify_needed_calls_attributes"
    MODIFY_SERVICE = "modify_service"
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

    SYSTEM_CONTEXT_PROMPT = """Your name is Prowler Studio and you are a security engineer specialized in cloud security and python
    developing working in a cloud security tool called Prowler. Mainly you work in all the parts of the proccess of check creation,
    a check is an automated security control that checks a specific security best practice in a cloud provider service.\n
    The Prowler structure is composed by:
    - The Prowler Providers: Python classes that is in charge of initialize the session and authentication with the provider.
    - The Prowler Services: Python classes that are in charge of make the calls to the provider services through the proper client that is set with the help of the provider. Normally it is composed in two parts:
        - The main class that is the one used to make the calls to the provider services.
        - Under the main class there are some extra classes that are the models that are used to store the data that is extracted from the provider services.
    - The Prowler Checks: Prowler checks are composed by two parts:
        - The metadata that is a JSON file that contains the information about the check like the description, the severity of the check, the risk, the remediation steps, etc.
        - The code that is a Python class with one method called execute that is where the audit logic is implemented. It returns a list of findings with the status (PASS, FAIL, INFO) of the check and other relevant information for the user like the ID of resource affected and a extended status to give more information about the finding.\n"""

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
                "Extract the audit steps from the user check summary. You should extact the steps that will be followed in the check progammatically at a high level to successfully audit the proposed request.\n"
                "You MUST NOT take care about setting up the session or authentication or how findings are going to be stored or reported, ONLY the logic to see if the audited resource is compliant or not.\n"
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
            Step.IS_SERVICE_COMPLETE: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Based on the next audit steps, identify if the service class contains all the needed SDK calls and attributes required for the check implementation.\n"
                "FOCUS ONLY on data that can be extracted from the provider, other data such as a range of days, concrete tags, request value specifications, etc. will be added directly in the Check and not in the Service.\n"
                "You MUST return 'yes' if the service code has all the needed SDK calls and attributes, or 'no' if there are missing elements.\n"
                "You MUST NOT explain what is missing at this step, just a simple yes/no evaluation.\n"
                "Audit steps:\n"
                f"{kwargs.get('audit_steps', '')}\n"
                "Service Code:\n"
                f"{kwargs.get('service_code', '')}\n"
            ),
            Step.IDENTIFY_NEEDED_CALLS_ATTRIBUTES: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Based on the audit steps, identify the specific SDK calls and attributes that need to be set up in the service class but are currently missing.\n"
                "FOCUS ONLY on data that can be extracted from the provider, other data such as a range of days, concrete tags, request value specifications, etc. will be added directly in the Check and not in the Service.\n"
                "If the service code has all the needed SDK calls and attributes, return 'none'. Otherwise, provide a detailed list of the SDK calls or attributes that need to be extracted/stored in the service class.\n"
                "You MUST NOT take care about setting up the session or authentication or how findings are going to be stored or reported, ONLY in SDK calls and how to get and store the needed data.\n"
                "Audit steps:\n"
                f"{kwargs.get('audit_steps', '')}\n"
                "Service Code:\n"
                f"{kwargs.get('service_code', '')}\n"
            ),
            Step.MODIFY_SERVICE: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Modify the service to include the missing SDK calls and attributes needed for the check implementation.\n"
                f"{30 * '-'}\n"
                "Missing Service Calls/Attributes:\n"
                f"{kwargs.get('missing_service_attributes', '')}\n"
                f"{30 * '-'}\n"
                "Service Code:\n"
                f"{30 * '-'}\n"
                f"{kwargs.get('service_code', '')}\n"
                f"{30 * '-'}\n"
                "You MUST JUST a Python code block with the entire code, NOT just the modified part.\n"  # The most optimal is force it to use the unified diff format, but this is easier for now.
            ),
            Step.CHECK_CODE_GENERATION: (
                f"SYSTEM CONTEXT: {SYSTEM_CONTEXT_PROMPT}"
                "Generate the Prowler check code based on the audit steps. Focus on the logic that will be executed in the check to audit the proposed request.\n"
                "NOT FOCUS on setting up the session or authentication or new SDK calls, the provider and service classes are already implemented.\n"
                "Please try to include all the logic in the execute method, do not include any other method or code outside the class.\n"
                f"Here are the most similar metadata of checks, you can take them as a reference, or if consider that is so similar you can just copy adapting to the user prompt:\n"
                "IMPORTANT NOTE: The ONLY status accepted is 'FAIL', 'PASS or 'INFO'. Please do not include any other status and if it is possible not use INFO status because it is not recommended.\n"
                f"The client object used in the check is the ONLY way to interact with the provider. You MUST NOT make calls to the SDK/API directly from the check, it must be done in the service class, which is the class that belongs the '{kwargs.get('check_name', '<service>').split('_')[0]}_client'. You MUST use the '{kwargs.get('check_name', '<service>').split('_')[0]}_client' that is also used in reference checks, the class code of this client is presented in the next code block delimited by dashes.\n"
                f"IMPORTANT NOTE: '{kwargs.get('check_name', '<service>').split('_')[0]}_client' contains all the attributes needed for the check, you MUST NOT add new attributes to this class, only use the existing ones.\n"
                f"IMPORTANT NOTE: Be careful with using external imported functions from lib as {kwargs.get('check_name', '<service>').split('_')[0]}_client method, usually the client does not have this kind of functions is more common to use extra functions that you can extract from the related checks code.\n"
                f"Here you have the base cases and steps to audit that you must cover in the check code:\n{kwargs.get('base_cases_and_steps', '')}\n"
                f"The check class name MUST be: {kwargs.get('check_name', '')}\n"
                "Other related checks examples:\n"
                f"{30 * '-'}\n"
                f"{kwargs.get('relevant_related_checks', '')}\n"
                f"{30 * '-'}\n"
                "Service Class Code:\n"
                f"{30 * '-'}\n"
                f"{kwargs.get('service_code', '')}\n"
                f"{30 * '-'}\n"
                f"Audit steps:\n{kwargs.get('audit_steps', '')}\n"
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
                f"{('Also the service code has needed some modifications, here you have the modifications in unified diff format:\n}' + (30 * '-') + kwargs.get('modified_service_code', '') + (30 * '-')) if kwargs.get('modified_service_code', '') else ''}"
                "Your task is pretify the final answer to the user, use mark down code blocks to make it more readable the metadata and the code, DO NOT MODIFY IT, only put in a markdown code block if it is not already.\n"
                f"Indicate to the user the check path where the check files must be stored in the Prowler repository, the folder path is: {kwargs.get('check_path', '')}, note that this is the name of the folder inside it there will be files with the same name but changing the file extension depending on the file."
                f' This folder MUST contain the "__init__.py" file, the metadata that MUST be stored in a file called "{kwargs.get("check_path", "").split("/")[-1]}.metadata.json" and the check code that MUST be stored in a file called "{kwargs.get("check_path", "").split("/")[-1]}.py".\n'
                f" {('And indicate that the service needs to be modified and display in a Markdown box the modifications.\n') if kwargs.get('modified_service_code', '') else ''}"
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
