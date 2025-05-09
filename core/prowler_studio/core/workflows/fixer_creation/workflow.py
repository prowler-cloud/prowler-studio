from llama_index.core import Settings
from llama_index.core.workflow import Context, Workflow, step
from llama_index.core.workflow.retry_policy import ConstantDelayRetryPolicy
from loguru import logger

from ...rag.vector_store import CheckMetadataVectorStore
from ...utils.model_chooser import llm_chooser
from .enum_steps import FixerCreationWorkflowStep
from .events import (
    FixerBasicInformation,
    FixerCodeResult,
    FixerCreationInput,
    FixerCreationResult,
)
from .prompts.prompt_manager import FixerCreationPromptManager


class FixerCreationWorkflow(Workflow):
    """Workflow to create a new fixer based on user input."""

    @step(retry_policy=ConstantDelayRetryPolicy(delay=10, maximum_attempts=2))
    async def workflow_setup(
        self, ctx: Context, start_event: FixerCreationInput
    ) -> FixerBasicInformation | FixerCreationResult:
        """Setup the workflow and sanitize the user input for next steps.

        Args:
            ctx: Workflow context.
            start_event: Event that triggered the workflow. It contains:
                - prowler_provider: Prowler provider to which the fixer will be added.
                - check_id: Check ID to which the fixer will be added.
                - llm_provider: Model provider to use for the LLM.
                - llm_reference: Model reference to use for the LLM.
                - api_key (optional): API key to use for the LLM.
        """
        logger.info("Initializing...")
        try:
            prowler_provider = start_event.prowler_provider
            await ctx.set("prowler_provider", prowler_provider)

            # For now we only support aws prowler provider
            if prowler_provider == "aws":
                # Check if the check_id is valid (exists in the inventory)
                check_metadata_vector_store = CheckMetadataVectorStore()

                available_checks = check_metadata_vector_store.check_inventory.get_available_checks_in_service(
                    provider_name=prowler_provider,
                    service_name=start_event.check_id.split("_")[0],
                )

                # TODO: Also check if the fixer already exists
                if start_event.check_id not in available_checks:
                    raise ValueError(
                        f"The check_id {start_event.check_id} does not exist in the inventory. Try to rebuild the RAG database with the latest Prowler repository."
                    )
                else:
                    await ctx.set("check_id", start_event.check_id)

                    # Get the check metadata and code
                    check_metadata = (
                        check_metadata_vector_store.check_inventory.get_check_metadata(
                            provider=prowler_provider,
                            service=start_event.check_id.split("_")[0],
                            check_id=start_event.check_id,
                        )
                    )

                    check_code = (
                        check_metadata_vector_store.check_inventory.get_check_code(
                            provider=prowler_provider,
                            service=start_event.check_id.split("_")[0],
                            check_id=start_event.check_id,
                        )
                    )

                    await ctx.set("check_metadata", check_metadata)
                    await ctx.set("check_code", check_code)

                    # Set the Settings.llm
                    Settings.llm = llm_chooser(
                        model_provider=start_event.llm_provider,
                        model_reference=start_event.llm_reference,
                        api_key=start_event.api_key,
                    )

                    await ctx.set("model_reference", start_event.llm_reference)

                    return FixerBasicInformation(
                        check_description=check_metadata["Description"],
                        check_code=check_code,
                        check_id=start_event.check_id,
                    )
            else:
                raise ValueError(
                    "Invalid prowler provider, for now is only supported aws. Sorry for the inconvenience, we are working to add more providers soon."
                )

        except Exception as e:
            logger.exception(e)
            return FixerCreationResult(
                status_code=1,
                user_answer="An error occurred while processing the user input. Please try again.",
                error_message=str(e),
            )

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=5))
    async def create_fixer_code(
        self, ctx: Context, fixer_basic_information: FixerBasicInformation
    ) -> FixerCodeResult | FixerCreationResult:
        """Generate the code for the fixer.
        TODO: Implement fixer code generation logic.
        """
        logger.info("Generating fixer code...")
        try:
            prompt_manager = FixerCreationPromptManager(
                model_reference=await ctx.get("model_reference", "generic")
            )
            await ctx.set("prompt_manager", prompt_manager)

            service_name = fixer_basic_information.check_id.split("_")[0]

            # Generate the fixer code
            fixer_code = await Settings.llm.acomplete(
                prompt=prompt_manager.get_prompt(
                    step=FixerCreationWorkflowStep.FIXER_CODE_GENERATION,
                    check_description=fixer_basic_information.check_description,
                    check_code=fixer_basic_information.check_code,
                    service_name=service_name,
                )
            )

            return FixerCodeResult(
                fixer_code=fixer_code.text,
                file_path=f"prowler/providers/aws/services/{service_name}/{fixer_basic_information.check_id}/{fixer_basic_information.check_id}_fixer.py",
            )

        except Exception as e:
            logger.exception(e)
            return FixerCreationResult(
                status_code=1,
                user_answer="An error occurred while generating the fixer code. Please try again.",
                error_message=str(e),
            )

    @step
    async def fixer_return(
        self, ctx: Context, fixer_code_result: FixerCodeResult
    ) -> FixerCreationResult:
        """Return the result of the fixer creation process.
        TODO: Implement final result formatting and return logic.
        """
        logger.info("Returning fixer creation result...")
        try:
            prompt_manager = await ctx.get("prompt_manager")
            final_answer = await Settings.llm.acomplete(
                prompt=prompt_manager.get_prompt(
                    step=FixerCreationWorkflowStep.PRETIFY_FINAL_ANSWER,
                    fixer_code=fixer_code_result.fixer_code,
                    file_path=fixer_code_result.file_path,
                    check_id="_".join(
                        fixer_code_result.file_path.split("/")[-1].split("_")[:-1]
                    ),
                )
            )

            return FixerCreationResult(
                status_code=0,
                user_answer=final_answer.text,
                fixer_code=fixer_code_result.fixer_code,
                fixer_path=fixer_code_result.file_path,
            )

        except Exception as e:
            logger.exception(e)
            return FixerCreationResult(
                status_code=1,
                user_answer="An error occurred while returning the fixer creation result. Please try again.",
                error_message=str(e),
            )
