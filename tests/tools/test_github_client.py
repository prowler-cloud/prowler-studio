"""Tests for GitHub REST API client."""

from typing import Any

import pytest

from tools.github_client import GitHubClient, GitHubIssueContent


class TestGitHubIssueContentToMarkdown:
    """Tests for GitHubIssueContent.to_markdown method."""

    def test_to_markdown_all_fields(self) -> None:
        """Convert issue with all fields to markdown."""
        content = GitHubIssueContent(
            number=123,
            title="Test Issue",
            body="This is the description.",
            state="open",
            labels=["bug", "high-priority"],
            url="https://github.com/owner/repo/issues/123",
        )

        result = content.to_markdown()

        assert "# Issue #123: Test Issue" in result
        assert "**State:** open" in result
        assert "**URL:** https://github.com/owner/repo/issues/123" in result
        assert "**Labels:** bug, high-priority" in result
        assert "## Description" in result
        assert "This is the description." in result

    def test_to_markdown_empty_labels(self) -> None:
        """Convert issue with empty labels list."""
        content = GitHubIssueContent(
            number=456,
            title="No Labels Issue",
            body="Description here.",
            state="closed",
            labels=[],
            url="https://github.com/owner/repo/issues/456",
        )

        result = content.to_markdown()

        assert "# Issue #456: No Labels Issue" in result
        assert "**State:** closed" in result
        assert "**Labels:**" not in result
        assert "Description here." in result

    def test_to_markdown_no_body(self) -> None:
        """Convert issue with empty body."""
        content = GitHubIssueContent(
            number=789,
            title="Empty Body Issue",
            body="",
            state="open",
            labels=["enhancement"],
            url="https://github.com/owner/repo/issues/789",
        )

        result = content.to_markdown()

        assert "(No description)" in result

    def test_to_markdown_no_url(self) -> None:
        """Convert issue without URL."""
        content = GitHubIssueContent(
            number=101,
            title="No URL Issue",
            body="Some body.",
            state="open",
            labels=[],
            url=None,
        )

        result = content.to_markdown()

        assert "**URL:**" not in result


class TestGitHubClientParseResponse:
    """Tests for GitHubClient._parse_response method."""

    def test_parse_response_full_data(self) -> None:
        """Parse complete API response."""
        client = GitHubClient(token="test-token")
        data = {
            "number": 42,
            "title": "Full Issue",
            "body": "Complete body text.",
            "state": "open",
            "labels": [{"name": "bug"}, {"name": "critical"}],
            "html_url": "https://github.com/owner/repo/issues/42",
        }

        result = client._parse_response(data)

        assert result.number == 42
        assert result.title == "Full Issue"
        assert result.body == "Complete body text."
        assert result.state == "open"
        assert result.labels == ["bug", "critical"]
        assert result.url == "https://github.com/owner/repo/issues/42"

    def test_parse_response_minimal_data(self) -> None:
        """Parse minimal API response with defaults."""
        client = GitHubClient(token="test-token")
        data: dict[str, Any] = {}

        result = client._parse_response(data)

        assert result.number == 0
        assert result.title == ""
        assert result.body == ""
        assert result.state == ""
        assert result.labels == []
        assert result.url is None

    def test_parse_response_null_body(self) -> None:
        """Parse response with null body."""
        client = GitHubClient(token="test-token")
        data = {
            "number": 1,
            "title": "Null Body",
            "body": None,
            "state": "open",
            "labels": [],
        }

        result = client._parse_response(data)

        assert result.body == ""

    def test_parse_response_labels_without_name(self) -> None:
        """Parse response with label objects missing name."""
        client = GitHubClient(token="test-token")
        data = {
            "number": 1,
            "title": "Test",
            "body": "Body",
            "state": "open",
            "labels": [{"name": "valid"}, {}, {"name": ""}],
        }

        result = client._parse_response(data)

        assert result.labels == ["valid"]


class TestGitHubClientInit:
    """Tests for GitHubClient initialization."""

    def test_init_with_explicit_token(self) -> None:
        """Initialize with explicit token."""
        client = GitHubClient(token="explicit-token")
        assert client.token == "explicit-token"

    def test_init_without_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Initialize without token (no env var) - should work for public repos."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        client = GitHubClient()
        assert client.token is None

    def test_init_with_env_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Initialize with token from environment."""
        monkeypatch.setenv("GITHUB_TOKEN", "env-token")
        client = GitHubClient()
        assert client.token == "env-token"
