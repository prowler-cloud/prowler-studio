"""GitHub REST API client for fetching issue content."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


class GitHubClientError(Exception):
    """Exception raised for GitHub API errors."""


@dataclass
class GitHubIssueContent:
    """Content fetched from a GitHub issue."""

    number: int
    title: str
    body: str
    state: str
    labels: list[str]
    url: str | None = None

    def to_markdown(self) -> str:
        """
        Convert the issue content to a Markdown string.

        Returns:
            Markdown-formatted issue content
        """
        sections: list[str] = [
            f"# Issue #{self.number}: {self.title}",
            "",
            f"**State:** {self.state}",
        ]

        if self.labels:
            sections.append(f"**Labels:** {', '.join(self.labels)}")

        sections.extend(["", "## Description", "", self.body or "(No description)", ""])

        return "\n".join(sections)


class GitHubClient:
    """
    Client for fetching GitHub issues via REST API.

    Uses Bearer token authentication.
    Tokens can be created at: https://github.com/settings/tokens
    """

    API_BASE_URL = "https://api.github.com"

    def __init__(self, token: str | None = None) -> None:
        """
        Initialize the GitHub client.

        Args:
            token: GitHub personal access token (falls back to GITHUB_TOKEN env var)

        Raises:
            GitHubClientError: If token is missing
        """
        self.token: str | None = token or os.getenv("GITHUB_TOKEN")

        if not self.token:
            raise GitHubClientError(
                "GitHub token required. Set GITHUB_TOKEN environment variable "
                "or pass token parameter."
            )

    def fetch_issue(
        self, owner: str, repo: str, issue_number: int
    ) -> GitHubIssueContent:
        """
        Fetch a GitHub issue by owner, repo, and number.

        Args:
            owner: Repository owner (e.g., 'prowler-cloud')
            repo: Repository name (e.g., 'prowler')
            issue_number: Issue number

        Returns:
            GitHubIssueContent with issue details

        Raises:
            GitHubClientError: If the API request fails
        """
        url: str = f"{self.API_BASE_URL}/repos/{owner}/{repo}/issues/{issue_number}"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            with httpx.Client() as client:
                response = client.get(
                    url,
                    headers=headers,
                    timeout=30.0,
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise GitHubClientError(
                    "Authentication failed. Check your GITHUB_TOKEN."
                ) from e
            elif e.response.status_code == 404:
                raise GitHubClientError(
                    f"Issue {owner}/{repo}#{issue_number} not found."
                ) from e
            else:
                raise GitHubClientError(
                    f"GitHub API error: {e.response.status_code} - {e.response.text}"
                ) from e
        except httpx.RequestError as e:
            raise GitHubClientError(f"Request failed: {e}") from e

        return self._parse_response(data)

    def _parse_response(self, data: dict[str, Any]) -> GitHubIssueContent:
        """
        Parse the GitHub API response into GitHubIssueContent.

        Args:
            data: Raw API response data

        Returns:
            Parsed GitHubIssueContent
        """
        labels: list[str] = [
            label.get("name", "")
            for label in data.get("labels", [])
            if label.get("name")
        ]

        return GitHubIssueContent(
            number=data.get("number", 0),
            title=data.get("title", ""),
            body=data.get("body", "") or "",
            state=data.get("state", ""),
            labels=labels,
            url=data.get("html_url"),
        )
