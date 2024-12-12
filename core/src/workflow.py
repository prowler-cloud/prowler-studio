import requests
from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step
from llama_index.core.workflow.retry_policy import ConstantDelayRetryPolicy
from loguru import logger

from core.src.events import (
    CheckBasicInformation,
    CheckMetadataInformation,
    CheckMetadataResult,
    CheckTestInformation,
    CheckTestsResult,
)
from core.src.utils.llm_structured_outputs import CheckMetadata
from core.src.utils.model_chooser import llm_chooser
from core.src.utils.prompt_loader import Step, load_prompt_template
from core.src.utils.prowler_information import (
    PROWLER_CHECKS,
    SUPPORTED_PROVIDERS,
    get_prowler_services,
)
from core.src.utils.rag import CheckDataManager, IndexedDataManager

DEFAULT_ERROR_MESSAGE = "Sorry but I cannot create a Prowler check with that information, please try again introducing more context about the check that you want to create, thanks for using Prowler."


class ChecKreationWorkflow(Workflow):
    """Workflow to create new Prowler check based on user input."""

    @step(retry_policy=ConstantDelayRetryPolicy(delay=10, maximum_attempts=3))
    async def workflow_setup(
        self, ctx: Context, start_event: StartEvent
    ) -> CheckBasicInformation | StopEvent:
        """Setup the workflow and sanitize the user input for next steps.

        Args:
            ctx: Workflow context.
            user_query: User input to start the workflow.
        """
        logger.info("Initializing...")
        try:
            user_query = start_event.get("user_query", "")

            if user_query:
                await ctx.set("user_query", user_query)

                Settings.llm = llm_chooser(
                    model_provider=start_event.get("model_provider", ""),
                    model_reference=start_event.get("model_reference", ""),
                )

                await ctx.set("model_provider", start_event.get("model_provider"))
                await ctx.set("model_reference", start_event.get("model_reference"))

                is_prowler_check = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.BASIC_FILTER,
                        model_reference=start_event.get("model_reference"),
                        user_query=user_query,
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
                            )
                        )
                    )
                    .text.strip()
                    .lower()
                )

                if prowler_provider not in SUPPORTED_PROVIDERS:
                    return StopEvent(result=DEFAULT_ERROR_MESSAGE)

                check_service = (
                    (
                        await Settings.llm.acomplete(
                            prompt=load_prompt_template(
                                step=Step.SERVICE_EXTRACTION,
                                model_reference=start_event.get("model_reference"),
                                user_query=user_query,
                                prowler_provider=prowler_provider,
                                services=get_prowler_services(prowler_provider),
                            )
                        )
                    )
                    .text.strip()
                    .lower()
                )

                return CheckBasicInformation(
                    prowler_provider=prowler_provider, service=check_service
                )

            else:
                raise ValueError("The provided user query is empty.")

        except ValueError as e:
            logger.error(str(e))
            return StopEvent()
        except Exception as e:
            logger.exception(e)
            return StopEvent()

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def security_analysis(
        self, ctx: Context, check_basic_info: CheckBasicInformation
    ) -> CheckMetadataInformation | CheckTestInformation | StopEvent:
        """Analyze the user input to extract the security best practices, kind of resource to audit and base cases to cover.

        Args:
            ctx: Workflow context.
            sanitized_user_input: Start event with the user input to analyze.
        """
        logger.info("Making security analysis...")
        try:
            best_practices = (
                await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.BEST_PRACTICE_EXTRACTION,
                        model_reference=await ctx.get("model_reference"),
                        user_query=await ctx.get("user_query"),
                    )
                )
            ).text.strip()

            indexed_data_manager = IndexedDataManager()

            check_manager = CheckDataManager(indexed_data_manager)

            # Check if the check already exists in the index data

            check_already_exists = check_manager.check_exists(best_practices)

            # Get relevant reference checks from the security analysis

            reference_check_names = check_manager.get_relevant_checks(
                best_practices,
                check_basic_info.prowler_provider,
                check_basic_info.service,
            )

            if check_already_exists:
                check_already_exists_message = (
                    "This check seems to already exist in Prowler."
                )

                if reference_check_names:
                    check_already_exists_message += (
                        " Here is a list of related checks that you should check before creating a new one:\n"
                        + "\n".join(f"- {check}" for check in reference_check_names)
                    )

                return StopEvent(result=check_already_exists_message)

            if not reference_check_names:
                # Extract 5 checks from same provider and service
                reference_check_names = PROWLER_CHECKS.get(
                    check_basic_info.prowler_provider, {}
                ).get(check_basic_info.service, [])[:5]

            if reference_check_names:
                await ctx.set("reference_check_names", reference_check_names)
            else:
                return StopEvent(result=DEFAULT_ERROR_MESSAGE)

            check_name = (
                (
                    await Settings.llm.acomplete(
                        prompt=load_prompt_template(
                            step=Step.CHECK_NAME_DESIGN,
                            model_reference=await ctx.get("model_reference"),
                            user_query=await ctx.get("user_query"),
                            service=check_basic_info.service,
                            best_practices=best_practices,
                            relevant_related_checks=reference_check_names,
                        )
                    )
                )
                .text.strip()
                .lower()
            )

            if check_name.split("_")[0] != check_basic_info.service:
                return StopEvent(result=DEFAULT_ERROR_MESSAGE)

            ctx.send_event(
                CheckMetadataInformation(
                    check_name=check_name,
                    check_description=best_practices,
                    prowler_provider=check_basic_info.prowler_provider,
                )
            )
            ctx.send_event(
                CheckTestInformation(
                    check_name=check_name,
                    check_description=best_practices,
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
    ) -> CheckMetadataResult:
        """Create the Prowler check based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        logger.info("Creating check metadata...")
        try:
            check_metadata = None

            # Download the relevant check metadata from the Prowler repository to give as reference to the prompt
            relevant_check_metadata = []

            for check_name in await ctx.get("reference_check_names"):
                metadata = requests.get(
                    f"https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/providers/{check_metadata_base_info.prowler_provider}/services/{check_name.split("_")[0]}/{check_name}/{check_name}.metadata.json"
                )
                relevant_check_metadata.append(metadata.text)

            check_metadata = await Settings.llm.astructured_predict(
                output_cls=CheckMetadata,
                prompt=PromptTemplate(
                    template=load_prompt_template(
                        step=Step.CHECK_METADATA_GENERATION,
                        model_reference=await ctx.get("model_reference"),
                        check_name=check_metadata_base_info.check_name,
                        check_description=check_metadata_base_info.check_description,
                        prowler_provider=check_metadata_base_info.prowler_provider,
                        relevant_related_checks=relevant_check_metadata,
                    )
                ),
            )

            return CheckMetadataResult(check_metadata=check_metadata)

        except ValueError as e:
            logger.error(str(e))
        except Exception as e:
            logger.exception(e)

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=5))
    async def create_check_tests(
        self, ctx: Context, check_test_info: CheckTestInformation
    ) -> CheckTestsResult:
        """Create the Prowler check tests based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        logger.info("Creating check tests...")
        try:
            check_tests = None

            check_tests = await Settings.llm.acomplete(
                prompt=load_prompt_template(
                    step=Step.CHECK_TESTS_GENERATION,
                    model_reference=await ctx.get("model_reference"),
                    check_name=check_test_info.check_name,
                    check_description=check_test_info.check_description,
                    prowler_provider=check_test_info.prowler_provider,
                )
            )

            return CheckTestsResult(check_tests=check_tests.text)

        except ValueError as e:
            logger.error(str(e))
        except Exception as e:
            logger.exception(e)

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=8))
    async def create_check_code(
        self, ctx: Context, trigger_events: CheckMetadataResult | CheckTestsResult
    ) -> StopEvent:
        """Create the Prowler check code based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        logger.info("Creating check code...")
        try:
            check_information = ctx.collect_events(
                trigger_events, [CheckMetadataResult, CheckTestsResult]
            )

            if check_information is None:
                return None
            else:
                # Generate the code for the check
                check_code = None

                relevant_related_checks = []

                for check_name in await ctx.get("reference_check_names"):
                    code = requests.get(
                        f"https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/providers/{check_information[0].check_metadata.Provider}/services/{check_information[0].check_metadata.ServiceName}/{check_name}/{check_name}.py"
                    )
                    relevant_related_checks.append(code.text)

                service_class = requests.get(
                    f"https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/providers/{check_information[0].check_metadata.Provider}/services/{check_information[0].check_metadata.ServiceName}/{check_information[0].check_metadata.ServiceName}_service.py"
                ).text

                check_code = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.CHECK_CODE_GENERATION,
                        model_reference=await ctx.get("model_reference"),
                        relevant_related_checks=relevant_related_checks,
                        check_description=getattr(
                            check_information[0].check_metadata, "Description", ""
                        ),
                        service_class=service_class,
                    )
                )

                return StopEvent(
                    result=f"Check metadata:\n{check_information[0].check_metadata}\n\nCheck tests:\n{check_information[1].check_tests}\n\nCheck code:\n{check_code.text}"
                )

        except ValueError as e:
            logger.error(str(e))
        except Exception as e:
            logger.exception(e)
