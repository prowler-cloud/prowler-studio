"""GitHub issue URL utilities."""

import re
from dataclasses import dataclass


@dataclass
class GitHubIssueInfo:
    """Parsed GitHub issue information."""

    owner: str
    repo: str
    issue_number: int

    @property
    def url(self) -> str:
        """Return the full GitHub issue URL."""
        return f"https://github.com/{self.owner}/{self.repo}/issues/{self.issue_number}"


def parse_github_issue_url(url: str) -> GitHubIssueInfo:
    """
    Parse a GitHub issue URL into components.

    Args:
        url: Full GitHub issue URL (e.g., https://github.com/owner/repo/issues/123)

    Returns:
        GitHubIssueInfo with parsed components

    Raises:
        ValueError: If URL format is invalid
    """
    pattern = r"^https?://github\.com/([^/]+)/([^/]+)/issues/(\d+)$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(
            f"Invalid GitHub issue URL format: {url}. "
            "Expected format: https://github.com/owner/repo/issues/123"
        )

    return GitHubIssueInfo(
        owner=match.group(1),
        repo=match.group(2),
        issue_number=int(match.group(3)),
    )
