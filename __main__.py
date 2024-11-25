# Description: This is the main entry point for the PoC. It will run the ChecKreationWorkflow with the user query and the model provider and reference.
import warnings

warnings.filterwarnings(
    action="ignore", category=UserWarning
)  # Only for the PoC, it looks like LLamaCPP integration with LLamaIndex have some issues with the warnings and pydantic models

import asyncio
import os
import sys

from core.src.utils.build_rag_dataset import build_vector_store
from core.src.workflow import ChecKreationWorkflow


async def run_check_creation_workflow(
    user_query: str, model_provider: str, model_reference: str
) -> dict:
    workflow = ChecKreationWorkflow(timeout=60, verbose=True)
    result = await workflow.run(
        user_query=user_query,
        model_provider=model_provider,
        model_reference=model_reference,
        verbose=True,
    )
    return result


if __name__ == "__main__":
    try:
        if len(sys.argv) < 2:
            print("Usage: python __main__.py <user_query>")
            sys.exit(1)

        user_query = sys.argv[1]

        # Check if the user query is empty
        if not user_query:
            print("User query can't be empty")
            sys.exit(1)

        # Check if index data for RAG is avaiable
        if not os.path.exists(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "core", "indexed_data_db"
            )
        ):
            # If not start with the process of extracting and indexing the data
            print(
                "Gathering data from prowler repo to have better experience, this may take a while..."
            )
            # For extracting the data from the prowler repository is needed a Github token, check first if is set in GIT_TOKEN environment variable if not ask for it
            github_token = os.getenv("GITHUB_TOKEN")
            if not github_token:
                github_token = input(
                    "Please enter a GitHub token to be able to extract the corresponding information from the Prowler GitHub repository: "
                )

            gemini_api_key = os.getenv("GOOGLE_API_KEY")

            if not gemini_api_key:
                gemini_api_key = input(
                    "Please enter a Google API key to be able to use the Gemini model: "
                )

            # Extract and index the data
            build_vector_store(
                github_token, "gemini", "models/text-embedding-004", gemini_api_key
            )

            print("Data extracted and indexed successfully!")

        result = asyncio.run(
            run_check_creation_workflow(
                user_query=user_query,
                model_provider="gemini",
                model_reference="models/gemini-1.5-flash",
            )
        )
        print(f"Result:\n{result}")
    except Exception as e:
        print(f"Error: {e}")
