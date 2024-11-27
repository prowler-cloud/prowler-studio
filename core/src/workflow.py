import requests
from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step

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
from core.src.utils.prowler_information import SUPPORTED_PROVIDERS, get_prowler_services
from core.src.utils.relevant_check_retriever import get_relevant_reference_checks

DEFAULT_ERROR_MESSAGE = "Sorry but I cannot create a Prowler check with that information, please try again introducing more context about the check that you want to create, thanks for using Prowler."


class ChecKreationWorkflow(Workflow):
    """Workflow to create new Prowler check based on user input."""

    @step
    async def workflow_setup(
        self, ctx: Context, start_event: StartEvent
    ) -> CheckBasicInformation | StopEvent:
        """Setup the workflow and sanitize the user input for next steps.

        Args:
            ctx: Workflow context.
            user_query: User input to start the workflow.
        """
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
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__.__name__}: [{e.__traceback__.tb_lineno}]: {e}"
            )

    @step
    async def security_analysis(
        self, ctx: Context, check_basic_info: CheckBasicInformation
    ) -> CheckMetadataInformation | CheckTestInformation | StopEvent:
        """Analyze the user input to extract the security best practices, kind of resource to audit and base cases to cover.

        Args:
            ctx: Workflow context.
            sanitized_user_input: Start event with the user input to analyze.
        """
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

            reference_check_names = get_relevant_reference_checks(
                security_analysis=best_practices,
                check_provider=check_basic_info.prowler_provider,
                check_service=check_basic_info.service,
            )

            await ctx.set("reference_check_names", reference_check_names)

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
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__.__name__}: [{e.__traceback__.tb_lineno}]: {e}"
            )

    @step
    async def create_check_metadata(
        self, ctx: Context, check_metadata_base_info: CheckMetadataInformation
    ) -> CheckMetadataResult | StopEvent:
        """Create the Prowler check based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        try:
            check_metadata = None

            # Download the relevant check metadata from the Prowler repository to give as reference to the prompt
            relevant_check_metadata = []

            for check_name in await ctx.get("reference_check_names"):
                metadata = requests.get(
                    f"https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/providers/{check_metadata_base_info.prowler_provider}/services/{check_name.split("_")[0]}/{check_name}/{check_name}.metadata.json"
                )
                relevant_check_metadata.append(metadata.text)

            while not check_metadata:
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
                                relevant_related_checks=relevant_check_metadata,
                            )
                        ),
                    )
                except Exception:
                    pass

            return CheckMetadataResult(check_metadata=check_metadata)

        except ValueError as e:
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__.__name__}: [{e.__traceback__.tb_lineno}]: {e}"
            )

    @step
    async def create_check_tests(
        self, ctx: Context, check_test_info: CheckTestInformation
    ) -> CheckTestsResult:
        """Create the Prowler check tests based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
        try:
            check_tests = None

            while not check_tests:
                try:
                    check_tests = await Settings.llm.acomplete(
                        prompt=load_prompt_template(
                            step=Step.CHECK_TESTS_GENERATION,
                            model_reference=await ctx.get("model_reference"),
                            check_name=check_test_info.check_name,
                            check_description=check_test_info.check_description,
                            prowler_provider=check_test_info.prowler_provider,
                        )
                    )
                except Exception:
                    pass

            check_test_result = CheckTestsResult(check_tests=check_tests.text)

            return check_test_result

        except ValueError as e:
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__.__name__}: [{e.__traceback__.tb_lineno}]: {e}"
            )

    @step
    async def create_check_code(
        self, ctx: Context, trigger_events: CheckMetadataResult | CheckTestsResult
    ) -> StopEvent:
        """Create the Prowler check code based on the user input.

        Args:
            ctx: Workflow context.
            check_metadata: Structured information extracted from the user query to create the check metadata.
        """
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
                        f"https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/providers/{check_information[0].check_metadata.Provider}/services/{check_name.split('_')[0]}/{check_name}/{check_name}.py"
                    )
                    relevant_related_checks.append(code.text)

                while not check_code:
                    try:
                        check_code = await Settings.llm.acomplete(
                            prompt=load_prompt_template(
                                step=Step.CHECK_CODE_GENERATION,
                                model_reference=await ctx.get("model_reference"),
                                check_metadata=check_information[0].check_metadata,
                                check_tests=check_information[1].check_tests,
                                relevant_related_checks=relevant_related_checks,
                            )
                        )
                    except Exception:
                        pass

                return StopEvent(
                    result=f"Check metadata:\n{check_information[0].check_metadata}\n\nCheck tests:\n{check_information[1].check_tests}\n\nCheck code:\n{check_code.text}"
                )

        except ValueError as e:
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__}: [{e.__traceback__.tb_lineno}]: {e}"
            )
