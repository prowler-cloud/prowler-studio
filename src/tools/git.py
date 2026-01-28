"""Git repository tools."""

from git import Repo
from git.exc import GitCommandError
from rich import print

# Constants
DEFAULT_BRANCH: str = "master"


def commit_changes(
    repo: Repo,
    message: str,
    paths: list[str] | None = None,
) -> str:
    """
    Stage and commit changes to the repository.

    Args:
        repo: The git.Repo object
        message: Commit message
        paths: Optional list of paths to stage (stages all if None)

    Returns:
        The commit SHA

    Raises:
        GitCommandError: If commit fails
    """
    try:
        # Stage changes
        if paths:
            for path in paths:
                repo.git.add(path)
        else:
            repo.git.add(".")

        # Check if there's anything to commit
        if not repo.is_dirty(index=True):
            print("[yellow]No changes to commit[/yellow]")
            return repo.head.commit.hexsha

        # Create commit
        commit = repo.index.commit(message)
        print(f"[green]✓ Committed: {commit.hexsha[:8]} - {message}[/green]")
        return commit.hexsha

    except GitCommandError as e:
        print(f"[red]✗ Commit failed: {e}[/red]")
        raise


def push_to_remote(
    repo: Repo,
    branch_name: str,
    remote_name: str = "origin",
) -> None:
    """
    Push branch to remote with upstream tracking.

    Args:
        repo: The git.Repo object
        branch_name: Name of the branch to push
        remote_name: Name of the remote (default: origin)

    Raises:
        GitCommandError: If push fails
    """
    try:
        print(f"[yellow]Pushing to {remote_name}/{branch_name}...[/yellow]")
        repo.git.push("-u", remote_name, branch_name)
        print(f"[green]✓ Pushed to {remote_name}/{branch_name}[/green]")

    except GitCommandError as e:
        print(f"[red]✗ Push failed: {e}[/red]")
        raise


def prepare_repo_for_work(repo: Repo, new_branch_name: str) -> None:
    """
    Prepare a git repository for work. For that is needed to:
    - Stash any existing changes
    - Switch to principal branch (master/main)
    - Pull latest changes
    - Create a new branch for the work

    For not losing any changes, the changes will be stashed and applied after the work is done.

    Args:
        repo: The git.Repo object
        new_branch_name: Name of the new branch to create for work

    """
    try:
        print("[bold]Preparing repository for work...[/bold]")

        # Step 1: Stash any uncommitted changes
        if repo.is_dirty() or repo.untracked_files:
            print("[yellow]⚠ Found uncommitted changes, stashing them...[/yellow]")
            repo.git.stash("save", "Automated stash before branch preparation")
            print("[green]✓ Changes stashed[/green]")
        else:
            print("No uncommitted changes to stash")

        # Step 2: Checkout principal branch
        current_branch: str = repo.active_branch.name
        if current_branch != DEFAULT_BRANCH:
            print(f"\nSwitching from '{current_branch}' to '{DEFAULT_BRANCH}'...")
            repo.git.checkout(DEFAULT_BRANCH)
            print(f"[green]✓ Checked out '{DEFAULT_BRANCH}'[/green]")
        else:
            print(f"\nAlready on '{DEFAULT_BRANCH}'")

        # Step 3: Pull latest changes
        print(f"\nPulling latest changes from origin/{DEFAULT_BRANCH}...")
        origin = repo.remotes.origin
        origin.pull()
        print("[green]✓ Repository updated with latest changes[/green]")

        # Show latest commit
        commit_message = repo.head.commit.message
        if isinstance(commit_message, bytes):
            commit_message = commit_message.decode("utf-8")
        print(
            f"Latest commit: {repo.head.commit.hexsha[:8]} - {commit_message.strip()}"
        )

        # Step 4: Create new branch for work
        print(f"\nCreating new branch '{new_branch_name}'...")

        # Check if branch already exists
        if new_branch_name in [branch.name for branch in repo.branches]:
            print(f"[yellow]⚠ Branch '{new_branch_name}' already exists[/yellow]")
            # Checkout existing branch
            repo.git.checkout(new_branch_name)
            print(f"[green]✓ Checked out existing branch '{new_branch_name}'[/green]")
        else:
            # Create and checkout new branch
            new_branch = repo.create_head(new_branch_name)
            new_branch.checkout()
            print(
                f"[green]✓ Created and checked out new branch '{new_branch_name}'[/green]"
            )

        print("[bold green]✓ Repository ready for work![/bold green]")
    except Exception as e:
        print(f"[bold red]✗ Error preparing repository: {e}[/bold red]")
        raise e


def rename_branch(repo: Repo, old_name: str, new_name: str) -> None:
    """
    Rename the current branch.

    Args:
        repo: The git.Repo object
        old_name: Current branch name
        new_name: New branch name

    Raises:
        GitCommandError: If rename fails
    """
    try:
        repo.git.branch("-m", old_name, new_name)
        print(f"[green]✓ Branch renamed: {old_name} → {new_name}[/green]")
    except GitCommandError as e:
        print(f"[red]✗ Failed to rename branch: {e}[/red]")
        raise


def generate_branch_name(check_name: str, ticket_key: str | None = None) -> str:
    """
    Generate branch name from check name and optional ticket key.

    Args:
        check_name: The check name (e.g., s3_bucket_public_access)
        ticket_key: Optional Jira ticket key (e.g., PROWLER-707)

    Returns:
        Branch name in format:
        - feat/<ticket>-<check_slug> if ticket provided
        - feat/<check_slug> if no ticket
    """
    check_slug = check_name.replace("_", "-")
    if ticket_key:
        return f"feat/{ticket_key.lower()}-{check_slug}"
    return f"feat/{check_slug}"
