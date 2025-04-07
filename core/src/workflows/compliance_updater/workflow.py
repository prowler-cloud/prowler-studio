from llama_index.core.workflow import StartEvent, StopEvent, Workflow, step
from llama_index.core.workflow.retry_policy import ConstantDelayRetryPolicy
from loguru import logger

from core.src.rag.vector_store import CheckMetadataVectorStore
from core.src.workflows.compliance_updater.events import (
    ComplianceBasicInformation,
    ComplianceDataResult,
)
from core.src.workflows.compliance_updater.utils.compliance_validator import (
    is_valid_prowler_compliance,
    validate_max_check_number_per_requirement,
    validate_confidence_threshold,
)


class ComplianceUpdaterWorkflow(Workflow):
    """Workflow to update compliance data with relevant checks."""

    @step(retry_policy=ConstantDelayRetryPolicy(delay=10, maximum_attempts=3))
    async def workflow_setup(
        self, start_event: StartEvent
    ) -> ComplianceBasicInformation | StopEvent:
        """Setup the workflow and sanitize the user input for next steps.
        Args:
            user_query: User input to start the workflow.
        """
        logger.info("Initializing...")
        try:
            compliance_data = start_event.get("compliance_data", "")
            max_check_number_per_requirement = start_event.get("max_check_number_per_requirement", 5)
            confidence_threshold = start_event.get("confidence_threshold", 0.6)
            
            if not validate_max_check_number_per_requirement(max_check_number_per_requirement):
                    raise ValueError(
                        f"Invalid max_check_number_per_requirement: {max_check_number_per_requirement}. It must be a value greater than 0."
                    )
            if not validate_confidence_threshold(confidence_threshold):
                raise ValueError(
                    f"Invalid confidence_threshold: {confidence_threshold}. It must be a float between 0 and 1."
                )

            if is_valid_prowler_compliance(compliance_data):
                return ComplianceBasicInformation(
                    prowler_provider=compliance_data.get("Provider", "").lower(),
                    compliance_data=compliance_data,
                    max_check_number_per_requirement=max_check_number_per_requirement,
                    confidence_threshold=confidence_threshold,
                )
            else:
                raise ValueError("Invalid Prowler compliance data format.")

        except Exception as e:
            logger.exception(e)
            return StopEvent(result=str(e))

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def get_compliance_checks(
        self, compliance_basic_info: ComplianceBasicInformation
    ) -> ComplianceDataResult:
        """Get the relevant checks for the compliance data.
        Args:
            check_basic_info: Basic information extracted from the user query to update the compliance data.
        """
        logger.info("Retrieving relevant checks...")
        try:
            check_metadata_vector_store = CheckMetadataVectorStore()

            output_data = []
            for requirement in compliance_basic_info.compliance_data["Requirements"]:
                check_description = requirement.get("Description", "")
                check_provider = compliance_basic_info.prowler_provider
                relevants_checks = check_metadata_vector_store.get_related_checks(
                    check_description=check_description,
                    num_checks=compliance_basic_info.max_check_number_per_requirement,
                    confidence_threshold=compliance_basic_info.confidence_threshold,
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
        except Exception as e:
            logger.exception(e)
            return StopEvent(result=str(e))

    @step(retry_policy=ConstantDelayRetryPolicy(delay=5, maximum_attempts=3))
    async def update_compliance(
        self, compliance_data: ComplianceDataResult
    ) -> StopEvent:
        """Update the compliance data with the relevant checks.
        Args:
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
        except Exception as e:
            logger.exception(e)
            return StopEvent(result=str(e))
