"""Jira URL utilities."""

import re
from dataclasses import dataclass


@dataclass
class JiraTicketInfo:
    """Parsed Jira ticket information."""

    site_url: str
    project_key: str
    issue_key: str


def parse_jira_url(url: str) -> JiraTicketInfo:
    """
    Parse a Jira ticket URL into components.

    Args:
        url: Full Jira ticket URL (e.g., https://mycompany.atlassian.net/browse/PROJ-123)

    Returns:
        JiraTicketInfo with parsed components

    Raises:
        ValueError: If URL format is invalid
    """
    # Pattern: https://site.atlassian.net/browse/PROJ-123
    pattern = r"^(https?://[^/]+)/browse/([A-Z][A-Z0-9]*-\d+)$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(
            f"Invalid Jira URL format: {url}. "
            "Expected format: https://site.atlassian.net/browse/PROJ-123"
        )

    site_url = match.group(1)
    issue_key = match.group(2)
    project_key = issue_key.split("-")[0]

    return JiraTicketInfo(
        site_url=site_url,
        project_key=project_key,
        issue_key=issue_key,
    )
