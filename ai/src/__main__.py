import warnings

warnings.filterwarnings(
    action="ignore", category=UserWarning
)  # Only for the PoC, it looks like LLamaCPP integration with LLamaIndex have some issues with the warnings and pydantic models

import asyncio
import sys

from workflow import ChecKreationWorkflow


async def run_check_creation_workflow(
    user_query: str, model_provider: str, model_reference: str
) -> dict:
    workflow = ChecKreationWorkflow(timeout=60, verbose=False)
    result = await workflow.run(
        user_query=user_query,
        model_provider=model_provider,
        model_reference=model_reference,
        verbose=False,
    )
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python __main__.py <user_query>")
        sys.exit(1)

    user_query = sys.argv[1]

    try:
        result = asyncio.run(
            run_check_creation_workflow(
                user_query=user_query,
                model_provider="gemini",
                model_reference="models/gemini-1.5-flash",
            )
        )
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")
