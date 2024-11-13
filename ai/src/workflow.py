import re

from llama_index.core import Settings
from llama_index.core.prompts.base import PromptTemplate
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step

from ai.src.events import CheckMetadataInformation
from ai.src.utils.llm_chooser import llm_chooser
from ai.src.utils.llm_structured_outputs import CheckBasicInformation
from ai.src.utils.prompt_loader import Step, load_prompt_template


class ChecKreationWorkflow(Workflow):
    """Workflow to create new Prowler check based on user input."""

    @step
    async def analyze_input(self, ctx: Context, start_event: StartEvent) -> StopEvent:
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

                # Start asking the model about the user query, extract if the user query is related to cloud security
                security_reasoning = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=Step.SECURITY_ANALYSIS,
                        model_reference=start_event.get("model_reference"),
                        user_query=user_query,
                    )
                )

                if str(security_reasoning).strip().lower() == "none" or re.search(
                    r"User prompt analysis:\nNONE", security_reasoning.text
                ):
                    return StopEvent(
                        result="Sorry, your user query seems to not have enough information to create a new check. Please provide more context."
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

                return CheckMetadataInformation(
                    check_name=check_basic_info.check_name,
                    check_description=security_reasoning.text.strip(),
                    prowler_provider=check_basic_info.prowler_provider,
                )
            else:
                raise ValueError("The provided user query is empty.")

        except ValueError as e:
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__.__name__}: [{e.__traceback__.tb_lineno}]: {e}"
            )
