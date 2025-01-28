from llama_index.core import Settings
from llama_index.core.workflow import Context, StopEvent, step
from loguru import logger

from core.src.events import CheckCodeResult, CheckMetadataResult
from core.src.utils.prompt_loader import Step, load_prompt_template
from core.src.workflow import ChecKreationWorkflow


# As llamadeploy does not support return JSON only return string, we need to use other workflow to just return string to Frontend
class APIChecKreationWorkflow(ChecKreationWorkflow):
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

                return StopEvent(result=final_answer.text)
        except Exception as e:
            logger.exception(e)


check_kreation_workflow = APIChecKreationWorkflow(timeout=500)
