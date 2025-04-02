
# Prowler Studio MCP Server

## Overview

Model Context Protocol (MCP) server for Prowler Studio. This server provides the main check creation workflow as a tool to be used by LLMs with MCP clients (Claude Desktop, Cursor, Clide, etc.).

## Components

### Tools

1. `create_prowler_check`:
    - Return a Prowler check metadata, code, service code changes and path in the repository.
        - Input:
            - `check_description`: Description of the check to be created.

## Installation

**Requirements**: The Prowler Studio API must be running. You can follow the instructions of the main README to install and run it.


## Usage

`uv --directory /Users/puchy/prowler_studio/mcp_server/ run mcp-server-prowler-studio --active`
