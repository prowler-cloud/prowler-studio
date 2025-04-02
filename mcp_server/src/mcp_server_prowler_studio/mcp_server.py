import httpx
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp_studio_server = FastMCP("Prowler Studio MCP Server")

# Constants
PROWLER_STUDIO_API_BASE = "http://localhost:4501"


@mcp_studio_server.tool("create_prowler_check")
async def create_prowler_check(check_description: str) -> str:
    """Create a Prowler check based on a description."

    This process gives all the information needed for a new Prowler check creation.
    If it is not possible to create the check, it will return a descriptive error message.

    Args:
        check_description (str): Description of the check.

    Returns:
        str: Response message.
    """
    async with httpx.AsyncClient(timeout=500.0) as client:
        response = await client.post(
            f"{PROWLER_STUDIO_API_BASE}/deployments/ChecKreationWorkflow/tasks/run",
            headers={"content-type": "application/json"},
            json={
                "input": f'{{"user_query": "{check_description}", "model_provider": "openai", "model_reference": "gpt-4o-mini"}}'
            },
        )
        response.raise_for_status()
        return response.text
