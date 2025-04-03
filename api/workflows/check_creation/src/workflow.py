from difflib import unified_diff

from llama_index.core import Settings
from llama_index.core.workflow import Context, StopEvent, step
from loguru import logger

from core.src.workflows.check_creation.events import (
    CheckCodeResult,
    CheckMetadataResult,
)
from core.src.workflows.check_creation.utils.prompt_steps_enum import (
    ChecKreationWorkflowStep,
)
from core.src.workflows.check_creation.workflow import ChecKreationWorkflow
from core.src.workflows.utils.prompt_manager import load_prompt_template


# As llamadeploy does not support return JSON, we need to use other workflow to just return parsed answer as string
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

                final_answer = await Settings.llm.acomplete(
                    prompt=load_prompt_template(
                        step=ChecKreationWorkflowStep.PRETIFY_FINAL_ANSWER,
                        model_reference=await ctx.get("model_reference"),
                        user_query=await ctx.get("user_query"),
                        check_metadata=check[0].check_metadata,
                        check_code=check[1].check_code,
                        modified_service_code=code_diff,
                        check_path=check_path,
                    )
                )

                return StopEvent(result=final_answer.text)

        except Exception as e:
            logger.exception(e)


check_creation_workflow = APIChecKreationWorkflow(timeout=500)
