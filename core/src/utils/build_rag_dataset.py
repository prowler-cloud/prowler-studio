import json
from datetime import datetime
from os.path import abspath, join
from typing import List, Optional

from llama_index.core import Settings, VectorStoreIndex
from llama_index.core.schema import Document
from llama_index.readers.github import GithubClient, GithubRepositoryReader

from core.src.utils.llm_chooser import embedding_model_chooser


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


def build_vector_store(
    github_token: str,
    model_provider: str,
    model_reference: str,
    api_key: Optional[str] = "",
):
    """
    Builds the RAG dataset.
    This function extracts the data from the Prowler GitHub repository, indexes it, and persists it.

    Args:
        github_token: The GitHub token used for authentication. Must be fine grained to access the repository.
        model_provider: Provider of the LLM model.
        model_reference: Reference to the LLM model, depending on the provider it can be a name, a path or a URL.
        api_key: API key to access the model. It is not a required parameter if the model provider does not require it.
    """
    prowler_documents = extract_prowler_data_from_github(github_token)

    Settings.embed_model = embedding_model_chooser(
        model_provider=model_provider, model_reference=model_reference, api_key=api_key
    )

    index = VectorStoreIndex.from_documents(
        documents=prowler_documents, show_progress=True
    )
    core_path = abspath(join(__file__, "../../../"))
    index_folder_name = "indexed_data_db"
    index.storage_context.persist(join(core_path, index_folder_name))

    metadata = {
        "date_of_creation": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model_provider": model_provider,
        "model_reference": model_reference,
    }

    with open(
        join(core_path, index_folder_name, "index_metadata.json"), "w"
    ) as metadata_file:
        json.dump(metadata, metadata_file)
