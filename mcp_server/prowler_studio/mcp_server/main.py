from loguru import logger
from mcp.server.fastmcp import FastMCP

from prowler_studio.core.workflows.check_creation.events import CheckCreationInput
from prowler_studio.core.workflows.check_creation.workflow import ChecKreationWorkflow
from prowler_studio.core.workflows.fixer_creation.events import FixerCreationInput
from prowler_studio.core.workflows.fixer_creation.workflow import FixerCreationWorkflow

# Initialize FastMCP server
mcp_server = FastMCP("Prowler Studio MCP Server")


@mcp_server.tool("create_prowler_fixer")
async def create_prowler_fixer(
    prowler_provider: str, check_id: str, llm_provider: str, llm_reference: str
) -> str:
    """Create a Prowler fixer based on a prowler provider and a check ID.

    This process gives all the information needed for a new Prowler fixer creation.
    If it is not possible to create the fixer, it will return a descriptive error message.

    Args:
        prowler_provider: Provider of the Prowler for now only "aws" is supported.
        check_id: ID of the check to which the fixer will be added.
        llm_provider: Provider of the LLM model, it can be "openai" or "gemini".
        llm_reference: Reference to the LLM model depending on the provider, it can be "gpt-4o" or "gpt-4o-mini" for OpenAI and "models/gemini-1.5-flash" for Gemini.

    Returns:
        All the steps to create the fixer with the code and metadata necessary.
    """
    try:
        workflow = FixerCreationWorkflow(timeout=300, verbose=False)
        result = await workflow.run(
            start_event=FixerCreationInput(
                prowler_provider=prowler_provider,
                check_id=check_id,
                llm_provider=llm_provider,
                llm_reference=llm_reference,
            ),
        )
        return result.user_answer
    except Exception as e:
        raise e


@mcp_server.tool("create_prowler_check")
async def create_prowler_check(
    check_description: str, llm_provider: str, llm_reference: str
) -> str:
    """Create a Prowler check based on a description."

    This process gives all the information needed for a new Prowler check creation.
    If it is not possible to create the check, it will return a descriptive error message.

    Args:
        check_description: Description of the check to be created.
        llm_provider: Provider of the LLM model, it can be "openai" or "gemini".
        llm_reference: Reference to the LLM model depending on the provider, it can be "gpt-4o" or "gpt-4o-mini" for OpenAI and "models/gemini-1.5-flash" for Gemini.

    Returns:
        All the steps to create the check with the code and metadata necessary.
    """
    try:
        workflow = ChecKreationWorkflow(timeout=300, verbose=False)
        result = await workflow.run(
            start_event=CheckCreationInput(
                user_query=check_description,
                llm_provider=llm_provider,
                llm_reference=llm_reference,
            ),
        )
        return result.user_answer
    except Exception as e:
        raise e


def main():
    try:
        logger.info("Starting Prowler Studio MCP Server...")
        mcp_server.run(transport="stdio")
    except Exception as e:
        logger.error(f"Error starting Prowler Studio MCP Server: {e}")
