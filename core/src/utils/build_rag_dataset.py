from typing import List

from llama_index.core.schema import Document
from llama_index.readers.github import GithubClient, GithubRepositoryReader


def extract_prowler_data_from_github(github_token: str) -> List[Document]:
    """
    Extracts data from the Prowler GitHub repository.
    This function connects to the Prowler GitHub repository using the provided GitHub token,
    reads the repository content, and filters the data to only include the relevant files (documentation and files directly related with checks).
    Args:
        github_token (str): The GitHub token used for authentication. Must be fine grained to access the repository.
    Returns:
        A list of Document objects containing the extracted data from the repository.
    """

    client = GithubClient(github_token=github_token)

    reader = GithubRepositoryReader(
        github_client=client,
        owner="prowler-cloud",
        repo="prowler",
        verbose=True,
        filter_directories=(
            ["docs/", "prowler/providers/", "tests/providers/"],
            GithubRepositoryReader.FilterType.INCLUDE,
        ),
        filter_file_extensions=(
            [".md", ".py", ".metadata.json"],
            GithubRepositoryReader.FilterType.INCLUDE,
        ),
    )

    return reader.load_data(branch="master")


def build_rag_dataset(github_token: str):
    # Extact Documents from Prowler repository
    extract_prowler_data_from_github(github_token)
