from llama_index.core import Settings
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step

from ai.src.events import CheckMetadataInformation
from ai.src.utils.llm_chooser import llm_chooser
from ai.src.utils.llm_structured_outputs import ResultPromptAnalysis
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

                # Load the prompt template
                prompt_template = load_prompt_template(
                    step=Step.INPUT_ANALYSIS,
                    model_reference=start_event.get("model_reference"),
                )

                # Keep trying to get the prompt analysis until it is successful
                prompt_analysis = None
                while not prompt_analysis:
                    try:
                        prompt_analysis = await Settings.llm.astructured_predict(
                            output_cls=ResultPromptAnalysis,
                            prompt=prompt_template,
                            user_prompt=user_query,
                        )

                        if (
                            prompt_analysis.security_logic == "NONE"
                            or prompt_analysis.provider == "NONE"
                            or prompt_analysis.service == "NONE"
                            or prompt_analysis.check_name == "NONE"
                        ):
                            return StopEvent(
                                result="The provided user query does not seem to contain all the necessary information to create a check."
                            )
                        else:
                            return CheckMetadataInformation(
                                check_name=prompt_analysis.check_name,
                                check_description=prompt_analysis.security_logic,
                                cloud_provider=prompt_analysis.provider,
                            )
                    except Exception:
                        pass
            else:
                raise ValueError("The provided user query is empty")

        except ValueError as e:
            return StopEvent(result=str(e))
        except Exception as e:
            return StopEvent(
                result=f"{e.__class__.__name__}: [{e.__traceback__.tb_lineno}]: {e}"
            )
