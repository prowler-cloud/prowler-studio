from enum import Enum


class FixerCreationWorkflowStep(str, Enum):
    FIXER_CODE_GENERATION = "fixer_code_generation"
    PRETIFY_FINAL_ANSWER = "pretify_final_answer"
