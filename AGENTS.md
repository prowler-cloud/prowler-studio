# Agent Development Guide

This document covers the architecture of Prowler Studio and the coding standards for developing its agents. Read [System Architecture](#system-architecture) to understand how the pieces fit together; read the development best practices that follow before adding or modifying an agent.

## Table of Contents

**System Architecture**

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Agents](#agents)
- [ChecKreatorAgent Flow](#checkreatoragent-flow)
- [Shared Tools](#shared-tools)
- [Logging & Observability](#logging--observability)
- [Main CLI Orchestration](#main-cli-orchestration)
- [Adding a New Agent](#adding-a-new-agent)

**Development Best Practices**

- [Architecture Principles](#architecture-principles)
- [Code Organization](#code-organization)
- [Method Decomposition](#method-decomposition)
- [Type Safety](#type-safety)
- [Named Parameters](#named-parameters)
- [Return Types with Pydantic](#return-types-with-pydantic)
- [Constants Management](#constants-management)
- [File Structure](#file-structure)
- [Examples](#examples)
- [Checklist for New Agents](#checklist-for-new-agents)

---

## System Architecture

### Overview

Prowler Studio uses the Claude Agent SDK to automate the creation of security checks for Prowler. The architecture separates each task (implementation, testing, compliance mapping, review, PR creation) into an independent agent. Agents run sequentially, with built-in verification and error-correction loops between them.

### Project Structure

```
prowler_studio/
├── src/
│   ├── core/
│   │   ├── main.py              # CLI entry point
│   │   └── exceptions.py        # Custom exceptions
│   ├── agents/
│   │   ├── base.py              # Agent base class
│   │   ├── implementation/      # ChecKreatorAgent for check creation
│   │   │   ├── agent.py         # Main agent implementation
│   │   │   ├── models.py        # Data models
│   │   │   └── prompts/         # Jinja2 prompt templates
│   │   ├── testing/             # TestingAgent for test generation
│   │   ├── review/              # ReviewAgent for code review
│   │   ├── compliance_mapping/  # ComplianceMappingAgent
│   │   └── pr_creation/         # PRCreationAgent for PR workflow
│   ├── tools/                   # Shared tools
│   │   ├── git.py               # Git operations and worktree management
│   │   ├── prowler.py           # Prowler-specific tools
│   │   ├── skills.py            # AI skills setup
│   │   ├── jira.py              # Jira URL parsing
│   │   ├── jira_client.py       # Jira API client
│   │   ├── github_issue.py      # GitHub issue URL parsing
│   │   ├── github_client.py     # GitHub REST API client
│   │   └── models.py            # Tool data models
│   └── utils/                   # Utilities
│       ├── prompts.py           # Prompt loading utilities
│       └── logging.py           # Logging utilities (agent output + tool calls)
└── pyproject.toml               # Project configuration
```

### Agents

Each agent is a self-contained unit that performs a specific task. Every agent inherits from the `Agent` base class in [src/agents/base.py](src/agents/base.py), implements `async run()`, and returns a typed result object.

**Current Agents:**

- **ChecKreatorAgent** ([src/agents/implementation/agent.py](src/agents/implementation/agent.py)) — Creates Prowler checks from tickets with automated verification.
- **TestingAgent** ([src/agents/testing/agent.py](src/agents/testing/agent.py)) — Generates and runs tests for checks with an auto-fix loop.
- **ReviewAgent** ([src/agents/review/agent.py](src/agents/review/agent.py)) — Reviews check implementations for quality and best practices.
- **ComplianceMappingAgent** ([src/agents/compliance_mapping/agent.py](src/agents/compliance_mapping/agent.py)) — Analyzes checks and adds compliance framework mappings.
- **PRCreationAgent** ([src/agents/pr_creation/agent.py](src/agents/pr_creation/agent.py)) — Commits changes and creates pull requests.

### ChecKreatorAgent Flow

The implementation agent follows this workflow:

1. **Setup** — Load prompts and configure the Claude Agent SDK with MCP tools.
2. **Implementation** — Claude agent creates the check based on ticket requirements.
3. **Discovery** — Automatically detect the created check from git changes.
4. **Verification Loop** (up to 5 attempts):
   - Run `prowler <provider> --list-checks` to verify the check loads.
   - If verification fails, provide error feedback to Claude.
   - Claude fixes the issues and verification runs again.
5. **Result** — Return success/failure with check details.

Key features:

- Uses Claude Agent SDK with a custom MCP server that exposes the `mkcheck` tool.
- Jinja2 templates for prompts in [src/agents/implementation/prompts/](src/agents/implementation/prompts/).
- Typed result models: `CheckImplementationResult`, `CheckDiscoveryResult`, `CheckVerificationResult`.

### Shared Tools

#### Git Tools ([src/tools/git.py](src/tools/git.py))

- `ensure_main_repo_exists()` — Clone the Prowler repo if it doesn't exist.
- `update_main_repo()` — Fetch and update the base branch before creating a worktree.
- `create_worktree()` / `remove_worktree()` — Manage isolated worktrees for parallel work.
- `get_worktree_name()` / `generate_branch_name()` / `rename_branch()` — Naming helpers.
- `commit_changes()` / `push_to_remote()` — Commit and push helpers used by PR creation.
- `prepare_repo_for_work()` — Legacy mode helper: stash changes, switch branches, pull updates.

#### Prowler Tools ([src/tools/prowler.py](src/tools/prowler.py))

- `mkcheck` (MCP tool) — Create check folder structure.
- `install_prowler_dependencies()` — Install Prowler with poetry.
- `verify_check_loaded()` — Verify the check appears in `prowler --list-checks`.

#### Skills Tools ([src/tools/skills.py](src/tools/skills.py))

- `setup_prowler_skills()` — Configure AI skills by running `skills/setup.sh --claude`.

#### Jira Tools ([src/tools/jira.py](src/tools/jira.py), [src/tools/jira_client.py](src/tools/jira_client.py))

- `parse_jira_url()` — Parse a Jira ticket URL into components (site_url, project_key, issue_key).
- `JiraClient.fetch_ticket()` — Fetch ticket content via the Jira REST API and return a `JiraTicketContent` (Markdown-renderable).

#### GitHub Tools ([src/tools/github_issue.py](src/tools/github_issue.py), [src/tools/github_client.py](src/tools/github_client.py))

- `parse_github_issue_url()` — Parse a GitHub issue URL into components (owner, repo, issue_number).
- `GitHubClient.fetch_issue()` — Fetch issue content via the GitHub REST API and return a `GitHubIssueContent` (Markdown-renderable). Reads `GITHUB_TOKEN` for higher rate limits.

### Logging & Observability

All workflow runs are logged to timestamped files in the `logs/` directory.

**Log Levels:**

- **INFO** (console + file) — Workflow progress, agent status, success/failure messages.
- **DEBUG** (file only) — Agent text output, tool calls with inputs/outputs.

**DEBUG-level tool call logging** captures all Claude agent tool usage:

```
2025-02-02 10:30:45 | DEBUG    | [TOOL CALL] Read (id=tool_abc123)
{
  "file_path": "/path/to/file.py"
}
2025-02-02 10:30:46 | DEBUG    | [TOOL RESULT] Read [OK]
1: def example():
2:     return "hello"
```

This is useful for debugging agent behavior and understanding what tools were invoked during a workflow run.

### Main CLI Orchestration

The CLI in [src/core/main.py](src/core/main.py) orchestrates agent execution through six stages (Stage 6 is skipped in `--local` mode):

```python
# 0. Prepare Prowler repository (worktree mode by default)
main_repo = ensure_main_repo_exists(working_dir, PROWLER_REPO_URL)
update_main_repo(main_repo)
repo = create_worktree(main_repo, worktree_path, branch_name)
setup_prowler_skills(repo.working_dir)
install_prowler_dependencies(repo.working_dir)

# Stage 1: Implementation - Create check from ticket
impl_agent = ChecKreatorAgent(working_dir=prowler_path, ...)
impl_result = asyncio.run(impl_agent.run())

# Stage 2: Testing - Generate and run tests
test_agent = TestingAgent(working_dir=prowler_path, check_name=impl_result.check_name, ...)
test_result = asyncio.run(test_agent.run())

# Stage 3: Compliance mapping - Add framework mappings
compliance_agent = ComplianceMappingAgent(working_dir=prowler_path, ...)
compliance_result = asyncio.run(compliance_agent.run())

# Stage 4: Review - Code review and quality checks
review_agent = ReviewAgent(working_dir=prowler_path, check_name=impl_result.check_name, ...)
review_result = asyncio.run(review_agent.run())

# Stage 5: Re-testing (conditional - only if review made changes)
if review_result.changes_made:
    retest_result = asyncio.run(test_agent.run())

# Stage 6: PR Creation (skipped if --local)
if not local:
    pr_agent = PRCreationAgent(working_dir=prowler_path, branch_name=branch_name, ...)
    pr_result = asyncio.run(pr_agent.run())
```

### Adding a New Agent

The example below uses a hypothetical `DocsAgent` that generates documentation for a check. Apply the same pattern for any new agent.

1. **Create agent structure:**

```bash
mkdir -p src/agents/docs
touch src/agents/docs/{__init__.py,agent.py,models.py}
mkdir src/agents/docs/prompts
```

2. **Implement the agent:**

```python
from pathlib import Path
from agents.base import Agent
from dataclasses import dataclass

@dataclass
class DocsResult:
    success: bool
    docs_path: str
    message: str = ""

class DocsAgent(Agent):
    def __init__(self, working_dir: Path, check_name: str, **kwargs):
        super().__init__(working_dir, **kwargs)
        self.check_name = check_name

    async def run(self) -> DocsResult:
        # Agent implementation using Claude Agent SDK
        # Load prompts, configure Claude options, run agent
        return DocsResult(success=True, docs_path="docs/checks/my_check.md")
```

3. **Add to main CLI:**

```python
from agents.docs.agent import DocsAgent

# After ChecKreatorAgent completes
docs_agent = DocsAgent(
    working_dir=prowler_path,
    check_name=impl_result.check_name,
)
docs_result = asyncio.run(docs_agent.run())
```

---

## Architecture Principles

### Base Agent Class

All agents inherit from the `Agent` base class ([src/agents/base.py](src/agents/base.py)), which provides:

- **`working_dir`**: Path to the working directory
- **`config`**: Agent-specific configuration from kwargs
- **`_process_agent_messages(client)`**: Shared method for processing Claude SDK responses
  - Streams `TextBlock` content to console and logs
  - Logs `ToolUseBlock` inputs at DEBUG level (`[TOOL CALL]`)
  - Logs `ToolResultBlock` outputs at DEBUG level (`[TOOL RESULT]`)

Agents must implement the abstract `run()` method.

### Single Responsibility Principle (SRP)

Each method should have **one clear purpose**. If a method does multiple things, break it down.

**❌ Bad Example:**
```python
async def run(self):
    # 127 lines doing: loading prompts, creating options, running agent,
    # discovering checks, verifying, fixing, and returning results
    ...
```

**✅ Good Example:**
```python
async def run(self):
    """High-level orchestration."""
    prompt = self._load_implementation_prompt()
    options = self._create_claude_options()

    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        discovery_result = self._discover_check_info()
        verification_result = await self._verify_and_fix_check(...)

    return CheckImplementationResult(...)
```

---

## Code Organization

### 1. File Structure

Organize agent code into separate, focused files:

```
src/agents/implementation/
├── __init__.py          # Public API exports
├── agent.py            # Agent business logic
├── models.py           # Pydantic models (data structures)
└── prompts/            # Jinja templates
    ├── implement_check.jinja
    └── fix_check.jinja
```

### 2. Separation of Concerns

**Models should be separate from business logic:**

- **models.py**: Data structures, validation, serialization
- **agent.py**: Business logic, orchestration, workflows
- **__init__.py**: Public API surface

**Benefits:**
- ✅ Easier to test models independently
- ✅ Prevents circular imports
- ✅ Models can be reused across agents
- ✅ Cleaner code organization

---

## Method Decomposition

### Break Down Large Methods

Keep methods **under 50 lines**. Extract logical sections into private methods.

**✅ Good Method Decomposition:**

```python
class ChecKreatorAgent(Agent):
    # Setup methods
    def _load_implementation_prompt(self) -> str: ...
    def _load_fix_prompt(self, check_name: str, message: str) -> str: ...
    def _create_claude_options(self) -> ClaudeAgentOptions: ...

    # Inherited from Agent base class:
    # async def _process_agent_messages(self, client: ClaudeSDKClient) -> None: ...

    # Business logic methods
    def _discover_check_info(self) -> CheckDiscoveryResult: ...
    async def _verify_and_fix_check(self, ...) -> CheckVerificationResult: ...

    # Main orchestration (clean and readable)
    async def run(self) -> CheckImplementationResult: ...
```

**Benefits:**
- ✅ Each method has a clear purpose
- ✅ Easier to test individual components
- ✅ Better code reusability
- ✅ Simpler to understand and maintain

---

## Type Safety

### Always Use Type Hints

**Every variable, parameter, and return type must have a type hint.**

**✅ Good Type Hints:**

```python
def _load_fix_prompt(self, check_name: str, verification_message: str) -> str:
    """Load the check fix prompt template."""
    fix_prompt_path: Path = Path(__file__).parent / "prompts" / "fix_check.jinja"
    return load_prompt(
        path=fix_prompt_path,
        context={
            "check_name": check_name,
            "verification_message": verification_message,
        },
    )

async def run(self) -> CheckImplementationResult:
    """Implement a Prowler check."""
    implement_check_prompt: str = self._load_implementation_prompt()
    options: ClaudeAgentOptions = self._create_claude_options()

    discovery_result: CheckDiscoveryResult = self._discover_check_info()
    verification_result: CheckVerificationResult = await self._verify_and_fix_check(...)

    return CheckImplementationResult(...)
```

**Benefits:**
- ✅ IDE autocomplete and IntelliSense
- ✅ Early error detection with type checkers (mypy, pyright)
- ✅ Self-documenting code
- ✅ Easier refactoring

---

## Named Parameters

### Always Use Named Parameters in Function Calls

**Never rely on positional arguments** (except for single, obvious parameters like `Path()`).

**❌ Bad Example:**
```python
result = self._load_fix_prompt(check_name, message)
await self._verify_and_fix_check(client, check_name, check_provider)
load_prompt(prompt_path, {"check_ticket": self.check_ticket})
```

**✅ Good Example:**
```python
result = self._load_fix_prompt(
    check_name=check_name,
    verification_message=message
)

await self._verify_and_fix_check(
    client=client,
    check_name=check_name,
    check_provider=check_provider
)

load_prompt(
    path=prompt_path,
    context={"check_ticket": self.check_ticket}
)
```

**Benefits:**
- ✅ Self-documenting code
- ✅ Prevents parameter order mistakes
- ✅ Easier to refactor (add/remove/reorder parameters)
- ✅ Clearer intent

---

## Return Types with Pydantic

### Never Return Tuples or Plain Dicts

**Always use Pydantic models** for return types. This makes the API explicit and self-documenting.

**❌ Bad Example:**
```python
def _discover_check_info(self) -> tuple[bool, str, str]:
    """What are these three values? Must check definition!"""
    return True, "my_check", "aws"

# Usage - unclear what each value represents
success, name, provider = self._discover_check_info()
```

**✅ Good Example:**
```python
# models.py
class CheckDiscoveryResult(BaseModel):
    """Result of discovering a check from repository changes."""
    success: bool = Field(description="Whether check discovery was successful")
    check_name: str = Field(default="", description="Name of the discovered check")
    check_provider: str = Field(
        default="", description="Provider of the check (e.g., 'aws', 'azure')"
    )

# agent.py
def _discover_check_info(self) -> CheckDiscoveryResult:
    """Crystal clear return type."""
    return CheckDiscoveryResult(
        success=True,
        check_name="my_check",
        check_provider="aws"
    )

# Usage - explicit and clear
result = self._discover_check_info()
if result.success:
    print(f"Found: {result.check_name} for {result.check_provider}")
```

**Benefits:**
- ✅ No need to check function definition to understand return structure
- ✅ IDE autocomplete on result fields
- ✅ Type validation at runtime
- ✅ Easy serialization/deserialization (`.model_dump()`, `.model_validate()`)
- ✅ Field descriptions serve as inline documentation
- ✅ Easier to add/modify fields without breaking callers

### Pydantic Model Best Practices

```python
from pydantic import BaseModel, Field

class CheckImplementationResult(BaseModel):
    """Always include a docstring."""

    # Use Field() with descriptions
    success: bool = Field(description="Whether implementation was successful")
    check_name: str = Field(default="", description="Name of the implemented check")
    message: str = Field(default="", description="Result message")
    attempts: int = Field(default=0, description="Number of verification attempts")

    # Use Optional for nullable fields
    error: str | None = Field(default=None, description="Error message if failed")

    # Provide sensible defaults when appropriate
```

---

## Constants Management

### Replace All Magic Numbers with Named Constants

**Magic numbers** make code hard to understand and maintain. Use class-level constants with descriptive names.

**❌ Bad Example:**
```python
tools_server = create_sdk_mcp_server(name="utils", version="1.0.0", tools=[mkcheck])

max_attempts = 5
while attempt < 5 and not success:
    ...

check_provider = check_path.parents[2].name  # What does 2 mean?
```

**✅ Good Example:**
```python
class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # MCP Server Configuration
    MCP_SERVER_NAME: str = "utils"
    MCP_SERVER_VERSION: str = "1.0.0"

    # Check Verification
    MAX_CHECK_VERIFICATION_ATTEMPTS: int = 5

    # Path Navigation
    PROVIDER_PATH_LEVEL: int = 3  # Number of parent levels to reach provider

    def _create_claude_options(self) -> ClaudeAgentOptions:
        tools_server = create_sdk_mcp_server(
            name=self.MCP_SERVER_NAME,
            version=self.MCP_SERVER_VERSION,
            tools=[mkcheck],
        )

    async def _verify_and_fix_check(self, ...) -> CheckVerificationResult:
        max_attempts: int = self.MAX_CHECK_VERIFICATION_ATTEMPTS
        while attempt < max_attempts and not success:
            ...

    def _discover_check_info(self) -> CheckDiscoveryResult:
        check_provider = check_path.parents[self.PROVIDER_PATH_LEVEL - 1].name
```

**Benefits:**
- ✅ Self-documenting code
- ✅ Easy to modify values in one place
- ✅ No mysterious numbers scattered throughout code
- ✅ Clear intent and meaning

### Constant Naming Convention

- Use `UPPER_CASE_WITH_UNDERSCORES` for constants
- Group related constants together
- Add comments when the purpose isn't obvious
- Type hint constants for additional clarity

---

## File Structure

### Complete Agent Package Example

```
src/agents/implementation/
├── __init__.py
├── agent.py
├── models.py
└── prompts/
    ├── implement_check.jinja
    └── fix_check.jinja
```

**__init__.py** - Public API:
```python
"""Implementation agent for creating Prowler checks."""

from agents.implementation.agent import ChecKreatorAgent
from agents.implementation.models import (
    CheckDiscoveryResult,
    CheckVerificationResult,
    CheckImplementationResult,
)

__all__ = [
    "ChecKreatorAgent",
    "CheckDiscoveryResult",
    "CheckVerificationResult",
    "CheckImplementationResult",
]
```

**models.py** - Data structures:
```python
"""Pydantic models for ChecKreatorAgent results."""

from pydantic import BaseModel, Field


class CheckDiscoveryResult(BaseModel):
    """Result of discovering a check from repository changes."""
    success: bool = Field(description="Whether check discovery was successful")
    check_name: str = Field(default="", description="Name of the discovered check")
    check_provider: str = Field(
        default="", description="Provider of the check (e.g., 'aws', 'azure')"
    )
```

**agent.py** - Business logic:
```python
"""Implementation agent for creating Prowler checks."""

from pathlib import Path
from typing import Any

from agents.base import Agent
from agents.implementation.models import (
    CheckDiscoveryResult,
    CheckVerificationResult,
    CheckImplementationResult,
)


class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # Constants
    MCP_SERVER_NAME: str = "utils"
    MAX_CHECK_VERIFICATION_ATTEMPTS: int = 5

    def __init__(self, working_dir: Path, check_ticket: str, prowler_repo: Repo, **kwargs):
        super().__init__(working_dir, **kwargs)
        self.check_ticket: str = check_ticket
        self.prowler_repo: Repo = prowler_repo

    # Private helper methods
    def _load_implementation_prompt(self) -> str: ...
    def _discover_check_info(self) -> CheckDiscoveryResult: ...

    # Public interface
    async def run(self) -> CheckImplementationResult: ...
```

---

## Examples

### Complete Example: Before and After

**❌ BEFORE (Poor Practices):**

```python
class Agent:
    def run(self):
        # 127 lines of code
        prompt_path = Path(__file__).parent / "prompts" / "implement_check.jinja"
        prompt = load_prompt(prompt_path, {"check_ticket": self.ticket})

        server = create_sdk_mcp_server("utils", "1.0.0", [mkcheck])

        # ... lots of code ...

        max_attempts = 5
        attempt = 0
        success = False
        message = ""

        while attempt < 5 and not success:
            # ... more code ...
            pass

        # What does this tuple contain?
        return success, check_name, message, attempt
```

**✅ AFTER (Best Practices):**

```python
# models.py
class CheckImplementationResult(BaseModel):
    """Result of implementing a Prowler check."""
    success: bool = Field(description="Whether implementation was successful")
    check_name: str = Field(default="", description="Name of the implemented check")
    message: str = Field(default="", description="Result message")
    attempts: int = Field(default=0, description="Number of verification attempts")


# agent.py
class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # Constants
    MCP_SERVER_NAME: str = "utils"
    MCP_SERVER_VERSION: str = "1.0.0"
    MAX_CHECK_VERIFICATION_ATTEMPTS: int = 5

    def _load_implementation_prompt(self) -> str:
        """Load the check implementation prompt template."""
        prompt_path: Path = Path(__file__).parent / "prompts" / "implement_check.jinja"
        return load_prompt(path=prompt_path, context={"check_ticket": self.check_ticket})

    def _create_claude_options(self) -> ClaudeAgentOptions:
        """Create Claude agent options with tools and MCP servers."""
        tools_server: Any = create_sdk_mcp_server(
            name=self.MCP_SERVER_NAME,
            version=self.MCP_SERVER_VERSION,
            tools=[mkcheck],
        )
        return ClaudeAgentOptions(
            allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
            mcp_servers={"utils": tools_server},
            permission_mode="bypassPermissions",
            cwd=str(self.working_dir),
        )

    async def _verify_and_fix_check(
        self, client: ClaudeSDKClient, check_name: str, check_provider: str
    ) -> CheckVerificationResult:
        """Verify the check implementation and fix issues in a loop."""
        max_attempts: int = self.MAX_CHECK_VERIFICATION_ATTEMPTS
        attempt: int = 0
        success: bool = False
        message: str = ""

        while attempt < max_attempts and not success:
            attempt += 1
            success, message = verify_check_loaded(
                check_name=check_name,
                provider=check_provider,
                prowler_directory=Path(self.prowler_repo.working_dir),
            )
            # ... handle failures ...

        return CheckVerificationResult(
            success=success,
            message=message,
            attempts=attempt
        )

    async def run(self) -> CheckImplementationResult:
        """Implement a Prowler check."""
        implement_check_prompt: str = self._load_implementation_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        async with ClaudeSDKClient(options=options) as client:
            await client.query(implement_check_prompt)

            discovery_result: CheckDiscoveryResult = self._discover_check_info()
            if not discovery_result.success:
                return CheckImplementationResult(
                    success=False,
                    error="No check folders found in repository changes",
                )

            verification_result: CheckVerificationResult = await self._verify_and_fix_check(
                client=client,
                check_name=discovery_result.check_name,
                check_provider=discovery_result.check_provider,
            )

        return CheckImplementationResult(
            success=verification_result.success,
            check_name=discovery_result.check_name,
            message=verification_result.message,
            attempts=verification_result.attempts,
        )
```

---

## Checklist for New Agents

When creating a new agent, ensure:

- [ ] **File Structure**: Separate models.py, agent.py, __init__.py
- [ ] **Type Hints**: All variables, parameters, and return types are typed
- [ ] **Named Parameters**: All function calls use named parameters
- [ ] **Pydantic Models**: No tuples or plain dicts for return types
- [ ] **Constants**: All magic numbers replaced with named constants
- [ ] **Method Size**: No method exceeds 50 lines
- [ ] **Single Responsibility**: Each method has one clear purpose
- [ ] **Docstrings**: All classes and methods have docstrings
- [ ] **Public API**: __init__.py exports only what's needed
- [ ] **Tests**: Unit tests for all public methods

---

## Additional Resources

- [PEP 484 - Type Hints](https://peps.python.org/pep-0484/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Python Style Guide (PEP 8)](https://peps.python.org/pep-0008/)

**Remember: These practices exist to make our codebase maintainable and our team productive. Follow them consistently!**
