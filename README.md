# Prowler Studio

Extensible framework for automating Prowler security check development using Claude Code agents.

## Overview

Prowler Studio uses the Claude Agent SDK to automate the creation of security checks for Prowler. The architecture separates different tasks into independent agents that can be run sequentially, with built-in verification and error correction loops.

## Features

- **Agent-Based**: Each task (implementation, testing, PR creation) is a separate agent
- **Self-Correcting**: Automated verification and fix loops ensure checks load correctly
- **Claude Agent SDK**: Leverages Claude's latest agent capabilities with MCP server integration
- **Extensible**: Add new agents without modifying existing code
- **Reusable Tools**: Share utilities across all agents
- **Type-Safe**: Full Python type hints and strict mypy checking

## Quick Start

### Installation

```bash
# Install dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate
```

### Usage

Create a Prowler check from a local ticket file:

```bash
prowler-studio feat/my_new_check --ticket check_ticket.md
```

Create a Prowler check from a Jira ticket:

```bash
prowler-studio feat/my_new_check --jira-url https://mycompany.atlassian.net/browse/PROJ-123
```

With custom working directory:

```bash
prowler-studio feat/my_new_check -t check_ticket.md -w ./custom_work
```

> **Note**: You must provide either `--ticket` or `--jira-url`, not both.

## Project Structure

```
prowler_studio/
├── src/
│   ├── core/
│   │   ├── main.py              # CLI entry point
│   │   └── exceptions.py        # Custom exceptions
│   ├── agents/
│   │   ├── base.py              # Agent base class
│   │   └── implementation/      # ChecKreatorAgent for check creation
│   │       ├── agent.py         # Main agent implementation
│   │       ├── models.py        # Data models
│   │       └── prompts/         # Jinja2 prompt templates
│   ├── tools/                   # Shared tools
│   │   ├── git.py               # Git operations
│   │   ├── prowler.py           # Prowler-specific tools
│   │   ├── skills.py            # AI skills setup
│   │   ├── jira.py              # Jira URL parsing
│   │   └── models.py            # Tool data models
│   └── utils/                   # Utilities
│       └── prompts.py           # Prompt loading utilities
└── pyproject.toml               # Project configuration
```

## Architecture

### Agents

Agents are self-contained units that perform specific tasks. Each agent:
- Inherits from `Agent` base class in [src/agents/base.py](src/agents/base.py)
- Implements `async run()` method
- Returns a typed result object

**Current Agents:**
- **ChecKreatorAgent** ([src/agents/implementation/agent.py](src/agents/implementation/agent.py)): Creates Prowler checks from tickets with automated verification

**Future Agents:**
- **TestingAgent**: Writes tests for checks
- **PRCreationAgent**: Creates pull requests
- **ReviewSummaryAgent**: Generates review summaries

### ChecKreatorAgent Flow

The implementation agent follows this workflow:

1. **Setup**: Load prompts and configure Claude Agent SDK with MCP tools
2. **Implementation**: Claude agent creates the check based on ticket requirements
3. **Discovery**: Automatically detect the created check from git changes
4. **Verification Loop** (up to 5 attempts):
   - Run `prowler <provider> --list-checks` to verify check loads
   - If verification fails, provide error feedback to Claude
   - Claude fixes the issues and verification runs again
5. **Result**: Return success/failure with check details

Key features:
- Uses Claude Agent SDK with custom MCP server for `mkcheck` tool
- Jinja2 templates for prompts in [src/agents/implementation/prompts/](src/agents/implementation/prompts/)
- Typed result models: `CheckImplementationResult`, `CheckDiscoveryResult`, `CheckVerificationResult`

### Tools

#### Git Tools ([src/tools/git.py](src/tools/git.py))
- `prepare_repo_for_work()`: Stash changes, switch branches, pull updates

#### Prowler Tools ([src/tools/prowler.py](src/tools/prowler.py))
- `mkcheck` (MCP tool): Create check folder structure
- `install_prowler_dependencies()`: Install Prowler with poetry
- `verify_check_loaded()`: Verify check appears in `prowler --list-checks`

#### Skills Tools ([src/tools/skills.py](src/tools/skills.py))
- `setup_prowler_skills()`: Configure AI skills by running `skills/setup.sh --claude`

#### Jira Tools ([src/tools/jira.py](src/tools/jira.py))
- `parse_jira_url()`: Parse Jira ticket URL into components (site_url, project_key, issue_key)

### Main CLI Orchestration

The CLI in [src/core/main.py](src/core/main.py) orchestrates agent execution:

```python
# 1. Prepare Prowler repository
repo = Repo.clone_from(PROWLER_REPO_URL, prowler_path)
prepare_repo_for_work(repo, branch_name)
setup_prowler_skills(prowler_path)  # Configure AI skills
install_prowler_dependencies(prowler_path)

# 2. Run implementation agent (with ticket file or Jira URL)
agent = ChecKreatorAgent(
    working_dir=prowler_path,
    check_ticket=ticket_content,  # From --ticket file
    jira_url=jira_url,            # Or from --jira-url
    prowler_repo=repo,
)
result = asyncio.run(agent.run())

# 3. Future: Run additional agents
# testing_agent = TestingAgent(working_dir=working_dir)
# test_result = asyncio.run(testing_agent.run(check_name=result.check_name))
#
# pr_agent = PRCreationAgent(working_dir=working_dir)
# pr_result = asyncio.run(pr_agent.run(branch=branch_name))
```

## Adding a New Agent

1. **Create agent structure:**
```bash
mkdir -p src/agents/testing
touch src/agents/testing/{__init__.py,agent.py,models.py}
mkdir src/agents/testing/prompts
```

2. **Implement the agent:**
```python
from pathlib import Path
from agents.base import Agent
from dataclasses import dataclass

@dataclass
class TestingResult:
    success: bool
    tests_created: int
    message: str = ""

class TestingAgent(Agent):
    def __init__(self, working_dir: Path, check_name: str, **kwargs):
        super().__init__(working_dir, **kwargs)
        self.check_name = check_name

    async def run(self) -> TestingResult:
        # Agent implementation using Claude SDK
        # Load prompts, configure Claude options, run agent
        return TestingResult(success=True, tests_created=5)
```

3. **Add to main CLI:**
```python
from agents.testing.agent import TestingAgent

# After ChecKreatorAgent completes
test_agent = TestingAgent(
    working_dir=prowler_path,
    check_name=result.check_name
)
test_result = asyncio.run(test_agent.run())
```

## Development

### Pre-commit Features

The pre-commit hooks automatically run on `git commit` and include:
- **Ruff** - Fast Python linting and formatting
- **mypy** - Static type checking with strict mode
- **pyupgrade** - Automatic Python 3.12+ syntax upgrades
- **Bandit** - Security vulnerability scanning
- **interrogate** - Docstring coverage enforcement (80% minimum)
- **Commitizen** - Conventional commit message validation
- **Common hooks** - Trailing whitespace, YAML/TOML validation, etc.

### Setup Pre-commit Hooks

```bash
# Install dev dependencies (includes pre-commit and all tools)
uv sync --extra dev

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type commit-msg
```

### Running Quality Checks Manually

```bash
# Run all pre-commit hooks
pre-commit run --all-files

# Run specific tools
ruff check src/
mypy src/
bandit -r src/
interrogate src/
```

## Dependencies

- **typer**: CLI framework
- **gitpython**: Git repository operations
- **jinja2**: Template rendering for prompts
- **claude-agent-sdk**: Claude Agent SDK for AI agent orchestration
- **rich**: Terminal formatting and output

## Configuration

Configuration is managed through [pyproject.toml](pyproject.toml):
- Tool configurations (ruff, mypy, bandit, interrogate)
- Project metadata and dependencies
- Entry point: `prowler-studio` command

## License

[Apache License 2.0](LICENSE)
