from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from core.src.workflows.check_creation.events import CheckCreationInput
from core.src.workflows.check_creation.workflow import ChecKreationWorkflow

app = FastAPI(
    title="Prowler Studio API",
    description="API to use Prowler Studio core functionalities",
    version="0.0.1",
)


class CheckCreationRequest(BaseModel):
    user_query: str
    llm_provider: str
    llm_reference: str
    llm_api_key: Optional[str] = None


class CheckCreationResponse(BaseModel):
    user_answer: str
    error_message: Optional[str] = None
    check_path: Optional[str] = None
    check_code: Optional[str] = None
    check_metadata: Optional[dict] = None
    service_code: Optional[str] = None
    generic_remediation: Optional[str] = None


@app.post("/new-check", response_model=CheckCreationResponse)
async def create_check(request: CheckCreationRequest):
    try:
        workflow = ChecKreationWorkflow(timeout=300, verbose=False)
        result = await workflow.run(
            start_event=CheckCreationInput(
                user_input=request.user_query,
                llm_provider=request.llm_provider,
                llm_reference=request.llm_reference,
                api_key=request.llm_api_key,
            ),
        )

        return CheckCreationResponse(
            user_answer=result.user_answer if hasattr(result, "user_answer") else "",
            error_message=(
                result.error_message if hasattr(result, "error_message") else None
            ),
            check_path=result.check_path if hasattr(result, "check_path") else None,
            check_code=result.check_code if hasattr(result, "check_code") else None,
            check_metadata=(
                result.check_metadata.dict()
                if hasattr(result, "check_metadata") and result.check_metadata
                else None
            ),
            service_code=(
                result.service_code if hasattr(result, "service_code") else None
            ),
            generic_remediation=(
                result.generic_remediation
                if hasattr(result, "generic_remediation")
                else None
            ),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
