"""Jira REST API client for fetching ticket content."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


class JiraClientError(Exception):
    """Exception raised for Jira API errors."""


@dataclass
class JiraTicketContent:
    """Content fetched from a Jira ticket."""

    key: str
    summary: str
    description: str
    acceptance_criteria: str | None = None
    status: str | None = None
    issue_type: str | None = None

    def to_markdown(self) -> str:
        """
        Convert the ticket content to a Markdown string.

        Returns:
            Markdown-formatted ticket content
        """
        sections: list[str] = [
            f"# {self.key}: {self.summary}",
            "",
        ]

        if self.issue_type:
            sections.append(f"**Type:** {self.issue_type}")
        if self.status:
            sections.append(f"**Status:** {self.status}")
        if self.issue_type or self.status:
            sections.append("")

        if self.description:
            sections.extend(["## Description", "", self.description, ""])

        if self.acceptance_criteria:
            sections.extend(
                ["## Acceptance Criteria", "", self.acceptance_criteria, ""]
            )

        return "\n".join(sections)


class JiraClient:
    """
    Client for fetching Jira tickets via REST API v3.

    Uses Basic Auth with email + API token.
    API tokens can be created at: https://id.atlassian.com/manage-profile/security/api-tokens
    """

    def __init__(
        self,
        site_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
    ) -> None:
        """
        Initialize the Jira client.

        Args:
            site_url: Jira site URL (falls back to JIRA_SITE_URL env var)
            email: Jira account email (falls back to JIRA_EMAIL env var)
            api_token: Jira API token (falls back to JIRA_API_TOKEN env var)

        Raises:
            JiraClientError: If credentials or site URL are missing
        """
        self.site_url: str | None = site_url or os.getenv("JIRA_SITE_URL")
        self.email: str | None = (
            email or os.getenv("JIRA_EMAIL") or os.getenv("JIRA_USER_EMAIL")
        )
        self.api_token: str | None = api_token or os.getenv("JIRA_API_TOKEN")

        if not self.site_url:
            raise JiraClientError(
                "Jira site URL required. Set JIRA_SITE_URL environment variable "
                "or pass site_url parameter."
            )
        self.site_url = self.site_url.rstrip("/")

        if not self.email or not self.api_token:
            raise JiraClientError(
                "Jira credentials required. Set JIRA_EMAIL and JIRA_API_TOKEN "
                "environment variables or pass email and api_token parameters."
            )

    def fetch_ticket(self, issue_key: str) -> JiraTicketContent:
        """
        Fetch a Jira ticket by its key.

        Args:
            issue_key: The issue key (e.g., PROJ-123)

        Returns:
            JiraTicketContent with ticket details

        Raises:
            JiraClientError: If the API request fails
        """
        url: str = f"{self.site_url}/rest/api/3/issue/{issue_key}"
        # Credentials are validated in __init__, so these are guaranteed to be str
        assert self.email is not None and self.api_token is not None
        auth: tuple[str, str] = (self.email, self.api_token)

        try:
            with httpx.Client() as client:
                response = client.get(
                    url,
                    auth=auth,
                    headers={"Accept": "application/json"},
                    timeout=30.0,
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise JiraClientError(
                    "Authentication failed. Check your JIRA_EMAIL and JIRA_API_TOKEN."
                ) from e
            elif e.response.status_code == 404:
                raise JiraClientError(f"Issue {issue_key} not found.") from e
            else:
                raise JiraClientError(
                    f"Jira API error: {e.response.status_code} - {e.response.text}"
                ) from e
        except httpx.RequestError as e:
            raise JiraClientError(f"Request failed: {e}") from e

        return self._parse_response(data)

    def _parse_response(self, data: dict[str, Any]) -> JiraTicketContent:
        """
        Parse the Jira API response into JiraTicketContent.

        Args:
            data: Raw API response data

        Returns:
            Parsed JiraTicketContent
        """
        fields: dict[str, Any] = data.get("fields", {})

        # Extract basic fields
        key: str = data.get("key", "")
        summary: str = fields.get("summary", "")

        # Extract description (ADF format -> plain text)
        description: str = self._parse_adf_content(fields.get("description"))

        # Extract status and issue type
        status: str | None = None
        if status_obj := fields.get("status"):
            status = status_obj.get("name")

        issue_type: str | None = None
        if issue_type_obj := fields.get("issuetype"):
            issue_type = issue_type_obj.get("name")

        # Try to extract acceptance criteria from custom fields
        acceptance_criteria: str | None = self._extract_acceptance_criteria(fields)

        return JiraTicketContent(
            key=key,
            summary=summary,
            description=description,
            acceptance_criteria=acceptance_criteria,
            status=status,
            issue_type=issue_type,
        )

    def _parse_adf_content(self, adf: dict[str, Any] | None) -> str:
        """
        Parse Atlassian Document Format (ADF) content to plain text.

        Args:
            adf: ADF content structure or None

        Returns:
            Plain text representation
        """
        if not adf:
            return ""

        if isinstance(adf, str):
            return adf

        result: list[str] = []
        self._extract_text_from_adf(adf, result)
        return "\n".join(result)

    def _extract_text_from_adf(self, node: dict[str, Any], result: list[str]) -> None:
        """
        Recursively extract text from ADF nodes.

        Args:
            node: ADF node
            result: List to append text to
        """
        node_type: str = node.get("type", "")

        if node_type == "text":
            text: str = node.get("text", "")
            if text:
                result.append(text)
        elif node_type == "hardBreak":
            result.append("")
        elif node_type == "paragraph":
            content: list[dict[str, Any]] = node.get("content", [])
            para_text: list[str] = []
            for child in content:
                self._extract_text_from_adf(child, para_text)
            if para_text:
                result.append(" ".join(para_text))
            result.append("")
        elif node_type == "heading":
            level: int = node.get("attrs", {}).get("level", 1)
            content = node.get("content", [])
            heading_text: list[str] = []
            for child in content:
                self._extract_text_from_adf(child, heading_text)
            if heading_text:
                prefix: str = "#" * level
                result.append(f"{prefix} {' '.join(heading_text)}")
                result.append("")
        elif node_type == "bulletList":
            for item in node.get("content", []):
                self._extract_list_item(item, result, bullet="- ")
        elif node_type == "orderedList":
            for idx, item in enumerate(node.get("content", []), 1):
                self._extract_list_item(item, result, bullet=f"{idx}. ")
        elif node_type == "codeBlock":
            content = node.get("content", [])
            code_text: list[str] = []
            for child in content:
                self._extract_text_from_adf(child, code_text)
            if code_text:
                result.append("```")
                result.extend(code_text)
                result.append("```")
                result.append("")
        else:
            # Process content for other node types
            for child in node.get("content", []):
                self._extract_text_from_adf(child, result)

    def _extract_list_item(
        self, item: dict[str, Any], result: list[str], bullet: str
    ) -> None:
        """
        Extract text from a list item node.

        Args:
            item: List item node
            result: List to append text to
            bullet: Bullet prefix (e.g., "- " or "1. ")
        """
        item_text: list[str] = []
        for child in item.get("content", []):
            child_text: list[str] = []
            self._extract_text_from_adf(child, child_text)
            item_text.extend(child_text)
        if item_text:
            result.append(f"{bullet}{' '.join(item_text).strip()}")

    def _extract_acceptance_criteria(self, fields: dict[str, Any]) -> str | None:
        """
        Try to extract acceptance criteria from common custom field patterns.

        Args:
            fields: Issue fields

        Returns:
            Acceptance criteria text or None
        """
        # Common field names for acceptance criteria
        ac_field_names: list[str] = [
            "customfield_10020",  # Common in Jira Cloud
            "customfield_10101",  # Another common one
            "acceptance criteria",
            "acceptancecriteria",
        ]

        for field_name in ac_field_names:
            if value := fields.get(field_name):
                if isinstance(value, dict):
                    return self._parse_adf_content(value)
                elif isinstance(value, str):
                    return value

        return None
