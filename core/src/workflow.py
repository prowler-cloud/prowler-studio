from time import sleep

from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step
from llama_index.core.workflow.retry_policy import ConstantDelayRetryPolicy
from loguru import logger
from pydantic import ValidationError

from core.src.events import (
    CheckBasicInformation,
    CheckCodeInformation,
    CheckCodeResult,
    CheckMetadataInformation,
    CheckMetadataResult,
)
from core.src.rag.vector_store import CheckMetadataVectorStore
from core.src.utils.llm_structured_outputs import CheckMetadata
from core.src.utils.model_chooser import llm_chooser
from core.src.utils.prompt_loader import Step, load_prompt_template

DEFAULT_ERROR_MESSAGE = "Sorry but I cannot create a Prowler check with that information, please try again introducing more context about the check that you want to create."


class ChecKreationWorkflow(Workflow):
    """Workflow to create new Prowler check based on user input."""

    @step(retry_policy=ConstantDelayRetryPolicy(delay=10, maximum_attempts=3))
    async def workflow_setup(
        self, ctx: Context, start_event: StartEvent
    ) -> CheckBasicInformation | StopEvent:
        """Setup the workflow and sanitize the user input for next steps.

        Args:
            ctx: Workflow context.
            start_event: Event that triggered the workflow. It contains:
                - user_query: User input to create the check.
                - model_provider: Model provider to use for the LLM.
                - model_reference: Model reference to use for the LLM.
                - api_key (optional): API key to use for the LLM.
        """
        logger.info("Initializing...")
        try:
            user_query = start_event.get("user_query", "")

            if user_query:
                await ctx.set("user_query", user_query)

                Settings.llm = llm_chooser(
                    model_provider=start_event.get("model_provider", ""),
                    model_reference=start_event.get("model_reference", ""),
                    api_key=start_event.get("api_key", ""),
                )

                await ctx.set("model_provider", start_event.get("model_provider"))
                await ctx.set("model_reference", start_event.get("model_reference"))

                check_metadata_vector_store = CheckMetadataVectorStore()

                await ctx.set(
                    "check_metadata_vector_store", check_metadata_vector_store
                )

                available_providers = (
                    check_metadata_vector_store.check_inventory.get_available_providers()
                )

                is_prowler_check = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.BASIC_FILTER,
                        model_reference=start_event.get("model_reference"),
                        user_query=user_query,
                        valid_providers=available_providers,
                    )
                )

                if is_prowler_check.text.strip().lower() != "yes":
                    return StopEvent(result=DEFAULT_ERROR_MESSAGE)

                prowler_provider = (
                    (
                        await Settings.llm.acomplete(
                            prompt=load_prompt_template(
                                step=Step.PROVIDER_EXTRACTION,
                                model_reference=start_event.get("model_reference"),
                                user_query=user_query,
                                valid_providers=available_providers,
                            )
                        )
                    )
                    .text.strip()
                    .lower()
                )

                if prowler_provider not in available_providers:
                    return StopEvent(
                        result=f"Sorry but I cannot create a Prowler check for that provider, please try again with a supported provider ({', '.join(available_providers)})."
                    )

                # TODO: Add description for each service to improve the LLM predictions
                services_for_provider = check_metadata_vector_store.check_inventory.get_available_services_in_provider(
                    provider_name=prowler_provider
                )

                check_service = (
                    (
                        await Settings.llm.acomplete(
                            prompt=load_prompt_template(
                                step=Step.SERVICE_EXTRACTION,
                                model_reference=start_event.get("model_reference"),
                                user_query=user_query,
                                prowler_provider=prowler_provider,
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
                    return StopEvent(
                        result=f"Sorry but the check service that you are trying to create is not supported in {prowler_provider} provider, please try again with a supported service: {', '.join(services_for_provider)}."
                    )

                return CheckBasicInformation(
                    prowler_provider=prowler_provider, service=check_service
                )

            else:
                raise ValueError("The provided user query is empty.")

        except ValueError as e:
            logger.error(str(e))
            return StopEvent(
                result="An error occurred while processing the user input. Please try again."
            )
        except Exception as e:
            logger.exception(e)
            return StopEvent(
                result="An error occurred while processing the user input. Please try again."
            )

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def security_analysis(
        self, ctx: Context, check_basic_info: CheckBasicInformation
    ) -> CheckMetadataInformation | CheckCodeInformation | StopEvent:
        """Analyze the user input to extract the security best practices, kind of resource to audit and base cases to cover.

        Args:
            ctx: Workflow context.
            check_basic_info: Basic information extracted from the user query to create the check
        """
        logger.info("Making security analysis...")
        try:
            base_cases_and_steps = (
                await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.CHECK_BASE_CASES_AND_STEPS_EXTRACTION,
                        model_reference=await ctx.get("model_reference"),
                        user_query=await ctx.get("user_query"),
                    )
                )
            ).text.strip()

            check_description = (
                await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.CHECK_DESCRIPTION_GENERATION,
                        model_reference=await ctx.get("model_reference"),
                        user_query=await ctx.get("user_query"),
                        base_cases_and_steps=base_cases_and_steps,
                    )
                )
            ).text.strip()

            check_metadata_vector_store = await ctx.get("check_metadata_vector_store")
            check_already_exists = check_metadata_vector_store.check_exists(
                check_description
            )
            reference_check_names = check_metadata_vector_store.get_related_checks(
                check_description=check_description,
                num_checks=15,
            )[check_basic_info.prowler_provider][check_basic_info.service]

            if check_already_exists:
                check_already_exists_message = (
                    "This check seems to already exist in Prowler."
                )

                if reference_check_names:
                    check_already_exists_message += (
                        " Here is a list of related checks that you should check before creating a new one:\n"
                        + "\n".join(f"- {check}" for check in reference_check_names[:3])
                    )

                return StopEvent(result=check_already_exists_message)

            if not reference_check_names:
                # Extract the first 5 checks from the service
                reference_check_names = (
                    check_metadata_vector_store.get_available_checks_in_service(
                        provider_name=check_basic_info.prowler_provider,
                        service_name=check_basic_info.service,
                    )[:5]
                )

            if not reference_check_names:
                # TODO: Add a way to create a new check from scratch or searching other checks from other services
                return StopEvent(
                    result="\nIt seems that there are no checks available for this service in Prowler, sorry but I cannot create a new check for you."
                )

            check_name = (
                (
                    await Settings.llm.acomplete(
                        prompt=load_prompt_template(
                            step=Step.CHECK_NAME_DESIGN,
                            model_reference=await ctx.get("model_reference"),
                            user_query=await ctx.get("user_query"),
                            service=check_basic_info.service,
                            check_description=check_description,
                            relevant_related_checks=reference_check_names,
                        )
                    )
                )
                .text.strip()
                .lower()
            )

            if check_name.split("_")[0] != check_basic_info.service:
                return StopEvent(result=DEFAULT_ERROR_MESSAGE)

            check_path = f"prowler/providers/{check_basic_info.prowler_provider}/services/{check_basic_info.service}/{check_name}"
            await ctx.set("check_path", check_path)

            ctx.send_event(
                CheckMetadataInformation(
                    check_name=check_name,
                    check_description=check_description,
                    prowler_provider=check_basic_info.prowler_provider,
                    related_check_names=reference_check_names,
                )
            )
            ctx.send_event(
                CheckCodeInformation(
                    check_name=check_name,
                    base_cases_and_steps=base_cases_and_steps,
                    related_check_names=reference_check_names,
                    prowler_provider=check_basic_info.prowler_provider,
                )
            )

        except ValueError as e:
            logger.error(str(e))
        except Exception as e:
            logger.exception(e)

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=5))
    async def create_check_metadata(
        self, ctx: Context, check_metadata_base_info: CheckMetadataInformation
    ) -> CheckMetadataResult | StopEvent:
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

            for i in range(MAX_STRUCTURED_ATTEMPS):
                try:
                    check_metadata = await Settings.llm.astructured_predict(
                        output_cls=CheckMetadata,
                        prompt=PromptTemplate(
                            template=load_prompt_template(
                                step=Step.CHECK_METADATA_GENERATION,
                                model_reference=await ctx.get("model_reference"),
                                check_name=check_metadata_base_info.check_name,
                                check_description=check_metadata_base_info.check_description,
                                prowler_provider=check_metadata_base_info.prowler_provider,
                                relevant_related_checks_metadata=relevant_checks_metadata,
                            )
                        ),
                    )
                    break
                except Exception as e:
                    sleep(5)
                    if i == MAX_STRUCTURED_ATTEMPS - 1:
                        raise e

            return CheckMetadataResult(check_metadata=check_metadata)

        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            return StopEvent(
                result="Sorry but there was a validation error while creating the check metadata, please try again later or change the input to see if it is valid for the model."
            )
        except ValueError as e:
            logger.error(str(e))
            return StopEvent(result=DEFAULT_ERROR_MESSAGE)
        except Exception as e:
            logger.exception(e)
            return StopEvent(result=DEFAULT_ERROR_MESSAGE)

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=8))
    async def create_check_code(
        self, ctx: Context, check_code_info: CheckCodeInformation
    ) -> CheckCodeResult:
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

            service_class_code = (
                check_metadata_vector_store.check_inventory.get_service_code(
                    provider=check_code_info.prowler_provider,
                    service=check_name.split("_")[0],
                )
            )

            relevant_related_checks = "\n\n--------\n\n".join(relevant_related_checks)

            check_code = await Settings.llm.acomplete(
                prompt=load_prompt_template(
                    step=Step.CHECK_CODE_GENERATION,
                    model_reference=await ctx.get("model_reference"),
                    check_name=check_code_info.check_name,
                    base_cases_and_steps=check_code_info.base_cases_and_steps,
                    relevant_related_checks=relevant_related_checks,
                    service_class_code=service_class_code,
                    user_query=await ctx.get("user_query"),
                )
            )

            return CheckCodeResult(check_code=check_code.text)

        except ValueError as e:
            logger.error(str(e))
        except Exception as e:
            logger.exception(e)

    @step
    async def check_return(
        self,
        ctx: Context,
        trigger_events: CheckMetadataResult | CheckCodeResult,
    ) -> StopEvent:
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
                final_answer = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.PRETIFY_FINAL_ANSWER,
                        model_reference=await ctx.get("model_reference"),
                        user_query=await ctx.get("user_query"),
                        check_metadata=check[0].check_metadata,
                        check_code=check[1].check_code,
                        check_path=await ctx.get("check_path"),
                    )
                )

                # Give some posible remediation steps based on the final answer
                remediation = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.REMEDIATION_GENERATION,
                        model_reference=await ctx.get("model_reference"),
                        final_answer=final_answer.text,
                    )
                )

                return StopEvent(
                    result={
                        "answer": final_answer.text,
                        "metadata": check[0].check_metadata,
                        "code": check[1].check_code,
                        "check_path": await ctx.get("check_path"),
                        "remediation": remediation.text,
                        # TODO: Add tests to the final answer if requested
                    }
                )

        except Exception as e:
            logger.exception(e)
