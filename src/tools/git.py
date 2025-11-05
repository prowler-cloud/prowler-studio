"""Git repository tools."""

from git import Repo
from rich import print

# Constants
DEFAULT_BRANCH: str = "master"


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
