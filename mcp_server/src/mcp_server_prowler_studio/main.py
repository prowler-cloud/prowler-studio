from mcp_server import mcp_studio_server


def main():
    print("Starting MCP Prowler Studio Server...")
    mcp_studio_server.run(transport="stdio")


if __name__ == "__main__":
    main()
