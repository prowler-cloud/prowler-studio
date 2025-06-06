from difflib import unified_diff
from time import sleep

from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, Workflow, step
from llama_index.core.workflow.retry_policy import ConstantDelayRetryPolicy
from loguru import logger

from ...rag.vector_store import CheckMetadataVectorStore
from ...utils.model_chooser import llm_chooser
from .events import (
    CheckBasicInformation,
    CheckCodeResult,
    CheckCreationInput,
    CheckCreationResult,
    CheckMetadataInformation,
    CheckMetadataResult,
    CheckServiceInformation,
    CheckServiceResult,
)
from .prompts.prompt_manager import CheckCreationPromptManager
from .utils.check_metadata_model import CheckMetadata
from .utils.prompt_steps_enum import ChecKreationWorkflowStep


class ChecKreationWorkflow(Workflow):
    """Workflow to create new Prowler check based on user input."""

    @step(retry_policy=ConstantDelayRetryPolicy(delay=10, maximum_attempts=2))
    async def workflow_setup(
        self, ctx: Context, start_event: CheckCreationInput
    ) -> CheckBasicInformation | CheckCreationResult:
        """Setup the workflow and sanitize the user input for next steps.

        Args:
            ctx: Workflow context.
            start_event: Event that triggered the workflow. It contains:
                - user_query: User input to create the check.
                - llm_provider: Model provider to use for the LLM.
                - llm_reference: Model reference to use for the LLM.
                - api_key (optional): API key to use for the LLM.
        """
        logger.info("Initializing...")
        try:
            user_query = start_event.user_query
            await ctx.set("user_query", user_query)

            if user_query:
                Settings.llm = llm_chooser(
                    model_provider=start_event.llm_provider,
                    model_reference=start_event.llm_reference,
                    api_key=start_event.api_key,
                )

                await ctx.set("model_reference", start_event.llm_reference)

                check_metadata_vector_store = CheckMetadataVectorStore()

                await ctx.set(
                    "check_metadata_vector_store", check_metadata_vector_store
                )

                available_providers = (
                    check_metadata_vector_store.check_inventory.get_available_providers()
                )

                # Initialize prompt manager
                prompt_manager = CheckCreationPromptManager(
                    model_reference=start_event.get("model_reference", "")
                )
                await ctx.set("prompt_manager", prompt_manager)

                is_prowler_check = await Settings.llm.acomplete(
                    prompt=prompt_manager.get_prompt(
                        step=ChecKreationWorkflowStep.BASIC_FILTER,
                        user_prompt=user_query,
                        prowler_providers=available_providers,
                    )
                )

                if is_prowler_check.text.strip().lower() != "yes":
                    return CheckCreationResult(
                        status_code=1,
                        user_answer=is_prowler_check.text,
                    )

                prowler_provider = (
                    (
                        await Settings.llm.acomplete(
                            prompt=prompt_manager.get_prompt(
                                step=ChecKreationWorkflowStep.PROVIDER_EXTRACTION,
                                user_prompt=user_query,
                                prowler_providers=available_providers,
                            )
                        )
                    )
                    .text.strip()
                    .lower()
                )

                if prowler_provider not in available_providers:
                    return CheckCreationResult(
                        status_code=1,
                        user_answer=f"Sorry but I cannot create a Prowler check for that provider, please try again with a supported provider ({', '.join(available_providers)}).",
                    )

                # TODO: Add description for each service to improve the LLM predictions
                services_for_provider = check_metadata_vector_store.check_inventory.get_available_services_in_provider(
                    provider_name=prowler_provider
                )

                check_service = (
                    (
                        await Settings.llm.acomplete(
                            prompt=prompt_manager.get_prompt(
                                step=ChecKreationWorkflowStep.SERVICE_EXTRACTION,
                                user_prompt=user_query,
                                provider=prowler_provider,
                                services=services_for_provider,
                            )
                        )
                    )
                    .text.strip()
                    .lower()
                )

                # Ensure only alphanumeric characters in the service name
                check_service = "".join(
                    [char for char in check_service if char.isalnum()]
                )

                if check_service not in services_for_provider:
                    if check_service == "unknown":
                        return CheckCreationResult(
                            status_code=1,
                            user_answer=f"Sorry but I am not being able to detect the service you want to create the check for, could you be more specific and make sure that the service is currently supported for Prowler. The supported services for {prowler_provider} are: {', '.join(services_for_provider)}.",
                        )
                    else:
                        return CheckCreationResult(
                            status_code=1,
                            user_answer=f"Sorry but the check service that you are trying to create is not supported in {prowler_provider} provider, please try again with a supported service: {', '.join(services_for_provider)}.",
                        )
                # Summary of the user input to create the check

                user_input_summary = await Settings.llm.acomplete(
                    prompt=prompt_manager.get_prompt(
                        step=ChecKreationWorkflowStep.USER_INPUT_SUMMARY,
                        user_prompt=user_query,
                        prowler_provider=prowler_provider,
                        service=check_service,
                    )
                )

                return CheckBasicInformation(
                    user_input_summary=user_input_summary.text.strip(),
                    prowler_provider=prowler_provider,
                    service=check_service,
                )

            else:
                raise ValueError("The provided user query is empty.")

        except ValueError as e:
            logger.error(e)
            return CheckCreationResult(
                status_code=1,
                user_answer="An error occurred while processing the user input. Please try again.",
                error_message=str(e),
            )
        except Exception as e:
            logger.exception(e)
            return CheckCreationResult(
                status_code=2,
                error_message=f"Unexpected error occurred while processing the user input: {e}",
            )

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def user_input_analysis(
        self, ctx: Context, check_basic_info: CheckBasicInformation
    ) -> CheckMetadataInformation | CheckServiceInformation | CheckCreationResult:
        """Analyze the user input to extract the security best practices, kind of resource to audit and base cases to cover.

        Args:
            ctx: Workflow context.
            check_basic_info: Basic information extracted from the user query to create the check
        """
        logger.info("Analyzing user input...")
        try:
            prompt_manager = await ctx.get("prompt_manager")

            check_metadata_vector_store = await ctx.get("check_metadata_vector_store")
            check_already_exists = check_metadata_vector_store.check_exists(
                check_description=check_basic_info.user_input_summary
            )
            reference_check_names = (
                check_metadata_vector_store.get_related_checks(
                    check_description=check_basic_info.user_input_summary,
                    num_checks=15,
                )
                .get(check_basic_info.prowler_provider, {})
                .get(check_basic_info.service, [])
            )

            if not reference_check_names:
                # Extract the first 5 checks from the service
                reference_check_names = list(
                    check_metadata_vector_store.check_inventory.get_available_checks_in_service(
                        provider_name=check_basic_info.prowler_provider,
                        service_name=check_basic_info.service,
                    )
                )[:5]

                if not reference_check_names:
                    # TODO: Add a way to create a new check from scratch or searching other checks from other services
                    return CheckCreationResult(
                        status_code=1,
                        user_answer="Sorry but I cannot create a new check for this service because there are no checks available for it.",
                    )

            if check_already_exists:
                check_already_exists_message = (
                    "This check seems to already exist in Prowler."
                )

                if reference_check_names:
                    check_already_exists_message += (
                        " Here is a list of related checks that you should check before creating a new one:\n"
                        + "\n".join(f"- {check}" for check in reference_check_names[:3])
                    )

                return CheckCreationResult(
                    status_code=1,
                    user_answer=check_already_exists_message,
                )

            check_name = (
                (
                    await Settings.llm.acomplete(
                        prompt=prompt_manager.get_prompt(
                            step=ChecKreationWorkflowStep.CHECK_NAME_DESIGN,
                            prowler_service=check_basic_info.service,
                            check_description=check_basic_info.user_input_summary,
                            relevant_related_checks=reference_check_names,
                        )
                    )
                )
                .text.strip()
                .lower()
            )

            if check_name.split("_")[0] != check_basic_info.service:
                return CheckCreationResult(
                    status_code=1,
                    user_answer="Sorry but there was an internal error while designing the check name, please try again.",
                )

            audit_steps = (
                await Settings.llm.acomplete(
                    prompt=prompt_manager.get_prompt(
                        step=ChecKreationWorkflowStep.AUDIT_STEPS_EXTRACTION,
                        check_description=check_basic_info.user_input_summary,
                    )
                )
            ).text.strip()

            check_path = f"prowler/providers/{check_basic_info.prowler_provider}/services/{check_basic_info.service}/{check_name}"
            await ctx.set("check_path", check_path)

            ctx.send_event(
                CheckMetadataInformation(
                    user_input_summary=check_basic_info.user_input_summary,
                    check_name=check_name,
                    prowler_provider=check_basic_info.prowler_provider,
                    related_check_names=reference_check_names,
                )
            )
            ctx.send_event(
                CheckServiceInformation(
                    prowler_provider=check_basic_info.prowler_provider,
                    check_name=check_name,
                    audit_steps=audit_steps,
                    related_check_names=reference_check_names,
                )
            )

        except Exception as e:
            exception_message = f"An error occurred while analyzing the user input: {e}"
            logger.exception(exception_message)
            return CheckCreationResult(status_code=2, error_message=exception_message)

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=5))
    async def create_check_metadata(
        self, ctx: Context, check_metadata_base_info: CheckMetadataInformation
    ) -> CheckMetadataResult | CheckCreationResult:
        """Create the Prowler check based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        logger.info("Creating check metadata...")
        try:
            check_metadata_vector_store = await ctx.get("check_metadata_vector_store")
            relevant_checks_metadata = []
            MAX_STRUCTURED_ATTEMPS = 5

            for check_name in check_metadata_base_info.related_check_names:
                metadata = (
                    check_metadata_vector_store.check_inventory.get_check_metadata(
                        provider=check_metadata_base_info.prowler_provider,
                        service=check_metadata_base_info.check_name.split("_")[0],
                        check_id=check_name,
                    )
                )
                relevant_checks_metadata.append(metadata)

            metadata_generation_prompt = (await ctx.get("prompt_manager")).get_prompt(
                step=ChecKreationWorkflowStep.CHECK_METADATA_GENERATION,
                check_name=check_metadata_base_info.check_name,
                check_description=check_metadata_base_info.user_input_summary,
                prowler_provider=check_metadata_base_info.prowler_provider,
                relevant_related_checks_metadata=relevant_checks_metadata,
            )

            for i in range(MAX_STRUCTURED_ATTEMPS):
                try:
                    check_metadata = await Settings.llm.astructured_predict(
                        output_cls=CheckMetadata,
                        prompt=PromptTemplate(template=metadata_generation_prompt),
                    )
                    if "validation error" in check_metadata:
                        raise ValueError(
                            "Internal error creating check metadata. Please try again later."
                        )
                except Exception as e:
                    sleep(5)
                    if i == MAX_STRUCTURED_ATTEMPS - 1:
                        raise e

            return CheckMetadataResult(check_metadata=check_metadata)

        except Exception as e:
            logger.exception(e)
            return CheckCreationResult(
                status_code=2,
                error_message=f"An error occurred while creating the check metadata: {e}",
            )

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=5))
    async def modify_service(
        self, ctx: Context, check_service_info: CheckServiceInformation
    ) -> CheckServiceResult | CheckCreationResult:
        """Ensure if the service needs to be modified to create a new check and modify it if needed.

        Args:
            ctx: Workflow context.
            check_service_info: Information needed to modify the service to create a new check.
        """
        logger.info("Checking service...")
        try:
            prompt_manager = await ctx.get("prompt_manager")

            check_metadata_vector_store = await ctx.get("check_metadata_vector_store")

            service_code = check_metadata_vector_store.check_inventory.get_service_code(
                provider=check_service_info.prowler_provider,
                service=check_service_info.check_name.split("_")[0],
            )

            is_service_complete = (
                await Settings.llm.acomplete(
                    prompt=prompt_manager.get_prompt(
                        step=ChecKreationWorkflowStep.IS_SERVICE_COMPLETE,
                        service_class_code=service_code,
                        audit_steps=check_service_info.audit_steps,
                    )
                )
            ).text.strip()

            if is_service_complete.lower() == "no":
                # Identify the missing parts of the service
                missing_service_attributes = (
                    await Settings.llm.acomplete(
                        prompt=prompt_manager.get_prompt(
                            step=ChecKreationWorkflowStep.IDENTIFY_NEEDED_CALLS_ATTRIBUTES,
                            audit_steps=check_service_info.audit_steps,
                            service_class_code=service_code,
                        )
                    )
                ).text.strip()

                # Add the missing parts to the service
                service_code = (  # TODO: FOR SOME REASON THE EXECUTION (AT LEAST THE DEBUGGER) IS FREEZING HERE
                    await Settings.llm.acomplete(
                        prompt=prompt_manager.get_prompt(
                            step=ChecKreationWorkflowStep.MODIFY_SERVICE,
                            service_class_code=service_code,
                            missing_service_calls_attributes=missing_service_attributes,
                        )
                    )
                ).text

            return CheckServiceResult(
                service_code=service_code,
                check_name=check_service_info.check_name,
                prowler_provider=check_service_info.prowler_provider,
                related_check_names=check_service_info.related_check_names,
                audit_steps=check_service_info.audit_steps,
            )

        except Exception as e:
            logger.exception(e)
            return CheckCreationResult(
                status_code=2,
                error_message=f"An error occurred while modifying the service: {e}",
            )

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=8))
    async def create_check_code(
        self, ctx: Context, check_code_info: CheckServiceResult
    ) -> CheckCodeResult | CheckCreationResult:
        """Create the Prowler check code based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        logger.info("Creating check code...")
        try:
            check_metadata_vector_store = await ctx.get("check_metadata_vector_store")
            relevant_related_checks = []

            for check_name in check_code_info.related_check_names:
                code = check_metadata_vector_store.check_inventory.get_check_code(
                    provider=check_code_info.prowler_provider,
                    service=check_name.split("_")[0],
                    check_id=check_name,
                )
                relevant_related_checks.append(code)

            check_code = await Settings.llm.acomplete(
                prompt=(await ctx.get("prompt_manager")).get_prompt(
                    step=ChecKreationWorkflowStep.CHECK_CODE_GENERATION,
                    check_name=check_code_info.check_name,
                    service_name=check_code_info.check_name.split("_")[0],
                    audit_steps=check_code_info.audit_steps,
                    relevant_related_checks_code=relevant_related_checks,
                    service_class_code=check_code_info.service_code,
                )
            )

            # TODO: Syntax check the code before returning it
            original_service_code = (
                check_metadata_vector_store.check_inventory.get_service_code(
                    provider=check_code_info.prowler_provider,
                    service=check_name.split("_")[0],
                )
            )

            return CheckCodeResult(
                check_code=check_code.text,
                modified_service_code=(
                    check_code_info.service_code
                    if check_code_info.service_code != original_service_code
                    else ""
                ),
            )

        except Exception as e:
            logger.exception(e)
            return CheckCreationResult(
                status_code=2,
                error_message=f"An error occurred while creating the check code: {e}",
            )

    @step
    async def check_return(
        self,
        ctx: Context,
        trigger_events: CheckMetadataResult | CheckCodeResult,
    ) -> CheckCreationResult:
        """Return full check to user and stop the workflow.

        Args:
            ctx: Workflow context.
            trigger_events: Event that triggered the check return.
        """
        try:
            check = ctx.collect_events(
                trigger_events, [CheckMetadataResult, CheckCodeResult]
            )

            if check is None:
                return None
            else:
                logger.info("Returning check...")
                # Ask the LLM to pretify the final answer before returning it to the user
                check_path = await ctx.get("check_path")

                # Calculate the difference using difflib
                service_code = check[1].modified_service_code

                if service_code != "":
                    # Import the RAG to get the original service code
                    check_metadata_vector_store = await ctx.get(
                        "check_metadata_vector_store"
                    )
                    original_service_code = (
                        check_metadata_vector_store.check_inventory.get_service_code(
                            provider=check_path.split("/")[2],
                            service=check_path.split("/")[4],
                        )
                    )

                    code_diff = "\n".join(
                        unified_diff(
                            original_service_code.splitlines(),
                            service_code.splitlines()[1:-1],
                            fromfile=f"{check_path.split('/')[4]}_service.py",
                            tofile=f"modified_{check_path.split('/')[4]}_service.py",
                            lineterm="",
                        )
                    )
                else:
                    code_diff = ""

                prompt_manager = await ctx.get("prompt_manager")

                final_answer = await Settings.llm.acomplete(
                    prompt=prompt_manager.get_prompt(
                        step=ChecKreationWorkflowStep.PRETIFY_FINAL_ANSWER,
                        check_metadata=check[0].check_metadata.dict(),
                        check_code=check[1].check_code,
                        service_class_code_diff=code_diff,
                        check_path=check_path,
                        check_name=check_path.split("/")[-1],
                        service_class_path="/".join(check_path.split("/")[:-1]),
                        service_name=check_path.split("/")[4],
                    )
                )

                # Give some posible remediation steps based on the final answer
                remediation = await Settings.llm.acomplete(
                    prompt=prompt_manager.get_prompt(
                        step=ChecKreationWorkflowStep.REMEDIATION_GENERATION,
                        final_answer=final_answer.text,
                    )
                )

                return CheckCreationResult(
                    status_code=0,
                    user_answer=final_answer.text,
                    check_metadata=check[0].check_metadata,
                    check_code=check[1].check_code,
                    check_path=check_path,
                    generic_remediation=remediation.text,
                    service_code=(
                        check[1].modified_service_code
                        if check[1].modified_service_code
                        else None
                    ),
                )

        except Exception as e:
            logger.exception(e)
            return CheckCreationResult(
                status_code=2,
                error_message=f"An error occurred while returning the check: {e}",
            )
