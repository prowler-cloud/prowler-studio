from llama_index.core import Settings
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step
from llama_index.core.workflow.retry_policy import ConstantDelayRetryPolicy
from loguru import logger

from core.src.rag.vector_store import CheckMetadataVectorStore
from core.src.utils.model_chooser import llm_chooser
from core.src.workflows.compliance_updater.events import (
    ComplianceBasicInformation,
    ComplianceDataResult,
)


class ComplianceUpdaterWorkflow(Workflow):
    """Workflow to update compliance data with relevant checks."""

    @step(retry_policy=ConstantDelayRetryPolicy(delay=10, maximum_attempts=3))
    async def workflow_setup(
        self, ctx: Context, start_event: StartEvent
    ) -> ComplianceBasicInformation | StopEvent:
        """Setup the workflow and sanitize the user input for next steps.
        Args:
            ctx: Workflow context.
            user_query: User input to start the workflow.
        """
        logger.info("Initializing...")
        try:
            compliance_data = start_event.get("compliance_data", "")

            if compliance_data:
                await ctx.set("compliance_data", compliance_data)

                Settings.llm = llm_chooser(
                    model_provider=start_event.get("model_provider", ""),
                    model_reference=start_event.get("model_reference", ""),
                    api_key=start_event.get("api_key", ""),
                )

                await ctx.set("model_provider", start_event.get("model_provider"))
                await ctx.set("model_reference", start_event.get("model_reference"))

                return ComplianceBasicInformation(
                    prowler_provider=compliance_data.get("Provider", "").lower(),
                    service="",
                    compliance_data=compliance_data,
                )

            else:
                raise ValueError("The provided compliance data is empty.")

        except ValueError as e:
            logger.error(str(e))
            return StopEvent()
        except Exception as e:
            logger.exception(e)
            return StopEvent()

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def get_compliance_checks(
        self, ctx: Context, compliance_basic_info: ComplianceBasicInformation
    ) -> ComplianceDataResult:
        """Update the compliance data with the relevant checks.
        Args:
            ctx: Workflow context.
            check_basic_info: Basic information extracted from the user query to update the compliance data.
        """
        logger.info("Updating compliance data...")
        try:
            check_metadata_vector_store = CheckMetadataVectorStore()

            await ctx.set("check_metadata_vector_store", check_metadata_vector_store)

            output_data = []
            for requirement in compliance_basic_info.compliance_data["Requirements"]:
                check_description = requirement.get("Description", "")
                check_provider = compliance_basic_info.prowler_provider
                relevants_checks = check_metadata_vector_store.get_related_checks(
                    check_description=check_description,
                    confidence_threshold=0.6,
                ).get(check_provider, {})

                checks = []
                for check_list in relevants_checks.values():
                    checks.extend(check_list)

                output_data.append(
                    {
                        "Id": requirement.get("Id", ""),
                        "RelevantChecks": checks,
                    }
                )

            return ComplianceDataResult(
                original_compliance_data=compliance_basic_info.compliance_data,
                updated_compliance_data=output_data,
            )

        except ValueError as e:
            logger.error(str(e))
            return StopEvent()

        except Exception as e:
            logger.exception(e)
            return StopEvent()

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def update_compliance(
        self, ctx: Context, compliance_data: ComplianceDataResult
    ) -> StopEvent:
        """Update the compliance data with the relevant checks.
        Args:
            ctx: Workflow context.
            compliance_data: Compliance data with the relevant checks.
        """
        logger.info("Updating compliance data...")
        try:
            for requirement in compliance_data.updated_compliance_data:
                for original_requirement in compliance_data.original_compliance_data[
                    "Requirements"
                ]:
                    if requirement["Id"] == original_requirement["Id"]:
                        for check in requirement["RelevantChecks"]:
                            if check not in original_requirement["Checks"]:
                                original_requirement["Checks"].append(check)
                        break

            return StopEvent(result=compliance_data.original_compliance_data)
        except ValueError as e:
            logger.error(str(e))
            return StopEvent()

        except Exception as e:
            logger.exception(e)
            return StopEvent()
