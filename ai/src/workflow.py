from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step

from ai.src.events import (
    CheckMetadataInformation,
    CheckMetadataResult,
    CheckTestInformation,
    CheckTestsResult,
)
from ai.src.utils.llm_chooser import llm_chooser
from ai.src.utils.llm_structured_outputs import CheckBasicInformation, CheckMetadata
from ai.src.utils.prompt_loader import Step, load_prompt_template


class ChecKreationWorkflow(Workflow):
    """Workflow to create new Prowler check based on user input."""

    @step
    async def analyze_input(
        self, ctx: Context, start_event: StartEvent
    ) -> CheckMetadataInformation | CheckTestInformation | StopEvent:
        """Analyze user input to create check.

        It is required to pass in the start event a valid user query, model provider and model reference.

        Args:
            ctx (Context): Workflow context.
            start_event (StartEvent): Event with the user query, model provider and model reference.
        """
        try:
            Settings.llm = llm_chooser(
                model_provider=start_event.get("model_provider", ""),
                model_reference=start_event.get("model_reference", ""),
            )
            user_query = start_event.get("user_query", "")

            if user_query:
                # Set the model provider and reference in the context to be usable in the next steps
                await ctx.set("model_provider", start_event.get("model_provider"))
                await ctx.set("model_reference", start_event.get("model_reference"))

                # TODO: Add a step to check if the user query is related to cloud security

                # If security-related, analyze security requirements and best practices
                security_reasoning = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.SECURITY_ANALYSIS,
                        model_reference=start_event.get("model_reference"),
                        user_query=user_query,
                    )
                )

                # Extract structured information like the provider and service from the user query, keep asking until the user provides the information
                check_basic_info = None

                while not check_basic_info:
                    try:
                        check_basic_info = await Settings.llm.astructured_predict(
                            output_cls=CheckBasicInformation,
                            prompt=PromptTemplate(
                                template=load_prompt_template(
                                    step=Step.SERVICE_PROVIDER_EXTRACTION,
                                    model_reference=start_event.get("model_reference"),
                                    user_query=user_query,
                                    security_reasoning=security_reasoning.text,
                                )
                            ),
                        )

                        if (
                            check_basic_info.service
                            != check_basic_info.check_name.split("_")[0]
                        ):
                            check_basic_info = None

                    except Exception:
                        pass

                # Set the structured information in the context to be usable in the next steps
                await ctx.set("check_basic_info", check_basic_info)

                ctx.send_event(
                    CheckMetadataInformation(
                        check_name=check_basic_info.check_name,
                        check_description=security_reasoning.text.strip(),
                        prowler_provider=check_basic_info.prowler_provider,
                    )
                )
                ctx.send_event(
                    CheckTestInformation(
                        check_name=check_basic_info.check_name,
                        check_description=security_reasoning.text.strip(),
                        prowler_provider=check_basic_info.prowler_provider,
                    )
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
    async def create_check_metadata(
        self, ctx: Context, check_metadata_base_info: CheckMetadataInformation
    ) -> CheckMetadataResult | StopEvent:
        """Create the Prowler check based on the user input.

        Args:
            ctx (Context): Workflow context.
            check_metadata (CheckMetadataInformation): Structured information extracted from the user query to create the check metadata.
        """
        try:
            check_metadata = None

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
    async def create_check_test(
        self, ctx: Context, check_test_info: CheckTestInformation
    ) -> CheckTestsResult:
        """Create the Prowler check test based on the user input.

        Args:
            ctx (Context): Workflow context.
            check_metadata (CheckMetadata): Structured information extracted from the user query to create the check metadata.
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
            ctx (Context): Workflow context.
            check_metadata (CheckMetadata): Structured information extracted from the user query to create the check metadata.
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

                while not check_code:
                    try:
                        check_code = await Settings.llm.acomplete(
                            prompt=load_prompt_template(
                                step=Step.CHECK_CODE_GENERATION,
                                model_reference=await ctx.get("model_reference"),
                                check_metadata=check_information[0].check_metadata,
                                check_tests=check_information[1].check_tests,
                            )
                        )
                    except Exception:
                        pass

                return StopEvent(
                    result=f"Check metadata: {check_information[0].check_metadata}\n\nCheck tests: {check_information[1].check_tests}\n\nCheck code: {check_code.text}"
                )

        except ValueError as e:
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__}: [{e.__traceback__.tb_lineno}]: {e}"
            )
