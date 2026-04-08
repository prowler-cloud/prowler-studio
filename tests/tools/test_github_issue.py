"""Tests for GitHub issue URL parser."""

import pytest

from tools.github_issue import GitHubIssueInfo, parse_github_issue_url


class TestParseGitHubIssueUrl:
    """Tests for parse_github_issue_url function."""

    def test_valid_standard_url(self) -> None:
        """Parse standard GitHub issue URL."""
        url = "https://github.com/owner/repo/issues/123"
        result = parse_github_issue_url(url)

        assert result.owner == "owner"
        assert result.repo == "repo"
        assert result.issue_number == 123

    def test_valid_url_with_trailing_slash(self) -> None:
        """Parse URL with trailing slash."""
        url = "https://github.com/owner/repo/issues/123/"
        result = parse_github_issue_url(url)

        assert result.owner == "owner"
        assert result.repo == "repo"
        assert result.issue_number == 123

    def test_valid_url_with_fragment(self) -> None:
        """Parse URL with fragment identifier."""
        url = "https://github.com/owner/repo/issues/123#issuecomment-456"
        result = parse_github_issue_url(url)

        assert result.owner == "owner"
        assert result.repo == "repo"
        assert result.issue_number == 123

    def test_valid_url_with_query_params(self) -> None:
        """Parse URL with query parameters."""
        url = "https://github.com/owner/repo/issues/123?foo=bar"
        result = parse_github_issue_url(url)

        assert result.owner == "owner"
        assert result.repo == "repo"
        assert result.issue_number == 123

    def test_valid_url_with_trailing_slash_and_fragment(self) -> None:
        """Parse URL with trailing slash and fragment."""
        url = "https://github.com/owner/repo/issues/123/#comment"
        result = parse_github_issue_url(url)

        assert result.owner == "owner"
        assert result.repo == "repo"
        assert result.issue_number == 123

    def test_valid_http_url(self) -> None:
        """Parse HTTP (non-HTTPS) URL."""
        url = "http://github.com/owner/repo/issues/456"
        result = parse_github_issue_url(url)

        assert result.owner == "owner"
        assert result.repo == "repo"
        assert result.issue_number == 456

    def test_invalid_url_wrong_domain(self) -> None:
        """Reject URL from wrong domain."""
        url = "https://gitlab.com/owner/repo/issues/123"

        with pytest.raises(ValueError, match="Invalid GitHub issue URL format"):
            parse_github_issue_url(url)

    def test_invalid_url_missing_issue_number(self) -> None:
        """Reject URL without issue number."""
        url = "https://github.com/owner/repo/issues/"

        with pytest.raises(ValueError, match="Invalid GitHub issue URL format"):
            parse_github_issue_url(url)

    def test_invalid_url_non_numeric_issue(self) -> None:
        """Reject URL with non-numeric issue number."""
        url = "https://github.com/owner/repo/issues/abc"

        with pytest.raises(ValueError, match="Invalid GitHub issue URL format"):
            parse_github_issue_url(url)

    def test_invalid_url_missing_repo(self) -> None:
        """Reject URL without repo."""
        url = "https://github.com/owner/issues/123"

        with pytest.raises(ValueError, match="Invalid GitHub issue URL format"):
            parse_github_issue_url(url)

    def test_invalid_url_pull_request(self) -> None:
        """Reject pull request URL (must be issue)."""
        url = "https://github.com/owner/repo/pull/123"

        with pytest.raises(ValueError, match="Invalid GitHub issue URL format"):
            parse_github_issue_url(url)


class TestGitHubIssueInfo:
    """Tests for GitHubIssueInfo dataclass."""

    def test_url_property(self) -> None:
        """Verify url property generates correct URL."""
        info = GitHubIssueInfo(owner="prowler-cloud", repo="prowler", issue_number=42)

        assert info.url == "https://github.com/prowler-cloud/prowler/issues/42"
