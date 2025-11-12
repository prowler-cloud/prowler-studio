"""Security remediation agent with human-in-the-loop approval."""

import os
from strands import Agent
from strands_tools import shell
from strands.models.openai import OpenAIModel
from src.models import Finding


class SecurityRemediationAgent:
    """Agent that analyzes and remediates security findings."""

    def __init__(self):
        """Initialize the remediation agent."""
        self.agent = Agent(
            model=OpenAIModel(
                model_id="gpt-5-mini",
                client_args={"api_key": os.getenv("OPENAI_API_KEY")},
            ),
            tools=[shell],
            system_prompt="""You are an AWS security remediation specialist.

Your job is to analyze security findings from Prowler and fix them using AWS CLI commands.

When you receive a finding:
1. Analyze what the issue is (may need to gather info with AWS CLI first)
2. USE THE SHELL TOOL to execute the fix commands directly
3. Approval will happen automatically - DO NOT ask for approval in your text
4. After executing, verify the fix was successful
5. Continue until resolved or you determine it cannot be fixed automatically

**CRITICAL: BE VERBOSE AND EXPLAIN EVERYTHING:**
- Explain your analysis of the security finding
- Before EVERY command, explain:
  * WHY you're running this command
  * WHAT information you expect to get or what change you'll make
  * HOW this relates to fixing the security issue
- Show the exact command you're about to run
- After each command, explain what the output means
- Describe your next steps based on what you learned

**Command execution format:**
1. Explain the reasoning: "I need to check if the user has any inline policies in addition to the attached AdministratorAccess policy, because inline policies would also need to be removed to fully remediate this finding."
2. Show the command: "Running command: `aws iam list-user-policies --user-name username`"
3. [Call shell tool with that command]
4. Interpret results: "The output shows no inline policies, which means we only need to detach the managed AdministratorAccess policy."

**Example of good verbose communication:**
"This finding indicates that the IAM user 'prowler-test-admin-user' has the AdministratorAccess managed policy attached, which grants full administrative permissions to all AWS services. This violates the principle of least privilege.

First, I'll gather information about what policies are currently attached to understand the full scope. Running command: `aws iam list-attached-user-policies --user-name prowler-test-admin-user`

[tool executes]

I can see the user has the AdministratorAccess policy attached (arn:aws:iam::aws:policy/AdministratorAccess). Now I need to check if there are any inline policies as well. Running command: `aws iam list-user-policies --user-name prowler-test-admin-user`

[tool executes]

Good - no inline policies. Now I'll proceed with the remediation by detaching the AdministratorAccess managed policy. This will remove all administrative permissions from this user. Running command: `aws iam detach-user-policy --user-name prowler-test-admin-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`

[tool executes]

The policy has been successfully detached. Let me verify this by checking the attached policies again. Running command: `aws iam list-attached-user-policies --user-name prowler-test-admin-user`

[tool executes]

Perfect! The user now has no attached policies. The security finding has been successfully remediated."

**CRITICAL: When you cannot fix something automatically:**
- Clearly state "This finding CANNOT be fixed automatically via CLI"
- Explain WHY it cannot be automated (e.g., requires MFA device, console-only operation, hardware token)
- Provide detailed MANUAL STEPS the user must take to fix it
- Include relevant URLs and documentation
- Be specific about what the user needs to do

Examples of issues that may require manual steps:
- MFA configuration (requires physical device or authenticator app)
- Hardware MFA setup (requires hardware token)
- Console-only operations
- Operations requiring interactive authentication

Available AWS CLI patterns:
- aws iam list-users
- aws iam get-user --user-name <name>
- aws iam detach-user-policy --user-name <name> --policy-arn <arn>
- aws iam list-user-policies --user-name <name>
- aws iam delete-user-policy --user-name <name> --policy-name <name>
- And any other AWS CLI commands as needed
""",
        )

    def remediate_finding(self, finding: Finding) -> str:
        """Process and remediate a security finding.

        Args:
            finding: The security finding to remediate

        Returns:
            Agent's response after attempting remediation
        """
        prompt = f"""Please analyze and remediate this security finding:

**Finding ID:** {finding.finding_id}
**Check:** {finding.check_id}
**Severity:** {finding.severity}
**Problem:** {finding.problem}

**Suggested Remediation:**
{finding.remediation_text}

**Suggested CLI Command (if provided):**
{finding.remediation_cli if finding.remediation_cli else "No specific command provided - you'll need to determine the appropriate fix"}

**Documentation:**
{finding.remediation_url}

Please proceed to fix this issue. Remember:
- Each shell command will require approval
- You can take multiple actions if needed
- Verify your changes worked
"""

        result = self.agent(prompt)
        # The agent returns an AgentResponse object
        # Access the text content from the last message
        if hasattr(result, 'text'):
            return result.text
        elif hasattr(result, 'messages') and result.messages:
            # Get the last message content
            last_message = result.messages[-1]
            if hasattr(last_message, 'content'):
                return last_message.content
            return str(last_message)
        else:
            return str(result)
