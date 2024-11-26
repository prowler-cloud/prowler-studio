import requests
from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step

from core.src.events import (
    CheckMetadataInformation,
    CheckMetadataResult,
    CheckTestInformation,
    CheckTestsResult,
)
from core.src.utils.llm_chooser import llm_chooser
from core.src.utils.llm_structured_outputs import CheckBasicInformation, CheckMetadata
from core.src.utils.prompt_loader import Step, load_prompt_template
from core.src.utils.relevant_check_retriever import get_relevant_reference_checks


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

                name_relevant_reference_checks = get_relevant_reference_checks(
                    security_analysis=security_reasoning.text.strip(),
                    check_provider=check_basic_info.prowler_provider,
                    check_service=check_basic_info.service,
                )

                await ctx.set(
                    "name_relevant_reference_checks", name_relevant_reference_checks
                )

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

            # Download the relevant check metadata from the Prowler repository to give as reference to the prompt
            relevant_check_metadata = []

            for check_name in await ctx.get("name_relevant_reference_checks"):
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

                relevant_related_checks = []

                for check_name in await ctx.get("name_relevant_reference_checks"):
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
