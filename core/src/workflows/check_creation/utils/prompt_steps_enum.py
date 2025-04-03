from enum import Enum


class ChecKreationWorkflowStep(str, Enum):
    BASIC_FILTER = "basic_filter"
    PROVIDER_EXTRACTION = "provider_extraction"
    SERVICE_EXTRACTION = "service_extraction"
    USER_INPUT_SUMMARY = "user_input_summary"
    CHECK_NAME_DESIGN = "check_name_design"
    AUDIT_STEPS_EXTRACTION = "audit_steps_extraction"
    CHECK_METADATA_GENERATION = "check_metadata_generation"
    IS_SERVICE_COMPLETE = "is_service_complete"
    IDENTIFY_NEEDED_CALLS_ATTRIBUTES = "identify_needed_calls_attributes"
    MODIFY_SERVICE = "modify_service"
    CHECK_CODE_GENERATION = "check_code_generation"
    PRETIFY_FINAL_ANSWER = "pretify_final_answer"
    REMEDIATION_GENERATION = "remediation_generation"
