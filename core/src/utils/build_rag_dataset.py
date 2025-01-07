import json
from datetime import datetime
from os.path import abspath, join
from typing import List, Optional

from llama_index.core import Settings, VectorStoreIndex
from llama_index.core.schema import Document
from llama_index.readers.github import GithubClient, GithubRepositoryReader
from loguru import logger

from core.src.utils.model_chooser import embedding_model_chooser


def extract_prowler_metadata_from_github(github_token: str) -> List[Document]:
    """
    Extracts metadata from the Prowler GitHub repository.
    This function connects to the Prowler GitHub repository using the provided GitHub token,
    reads the repository and extracts the metadata from all AWS, Azure, GCP, and Kubernetes services.
    Args:
        github_token (str): The GitHub token used for authentication. Must be fine grained to access the repository.
    Returns:
        A list of Document objects containing the extracted metadata from the repository.
    """
    logger.info("Extracting metadata from the Prowler GitHub repository")
    prowler_metadata = []
    try:
        client = GithubClient(github_token=github_token)

        reader = GithubRepositoryReader(
            github_client=client,
            owner="prowler-cloud",
            repo="prowler",
            verbose=False,
            filter_directories=(
                [
                    "prowler/providers/aws/services/",
                    "prowler/providers/azure/services/",
                    "prowler/providers/gcp/services/",
                    "prowler/providers/kubernetes/services/",
                ],
                GithubRepositoryReader.FilterType.INCLUDE,
            ),
            filter_file_extensions=(
                [".json"],
                GithubRepositoryReader.FilterType.INCLUDE,
            ),
        )

        prowler_metadata = reader.load_data(branch="master")
    except Exception as e:
        logger.exception(
            f"An error occurred while extracting metadata from the Prowler GitHub repository: {e}"
        )
        raise e
    return prowler_metadata


def build_vector_store(
    github_token: str,
    model_provider: str,
    model_reference: str,
    api_key: Optional[str] = "",
    vector_store_path: Optional[str] = abspath(join(__file__, "../../../")),
) -> None:
    """
    Builds the RAG dataset.
    This function extracts the data from the Prowler GitHub repository, indexes it, and persists it.

    Args:
        github_token: The GitHub token used for authentication. Must be fine grained to access the repository.
        model_provider: Provider of the LLM model.
        model_reference: Reference to the LLM model, depending on the provider it can be a name, a path or a URL.
        api_key: API key to access the model. It is not a required parameter if the model provider does not require it.
        vector_store_path: Path to the indexed data storage.
    """
    logger.info("Building RAG dataset")
    try:
        Settings.embed_model = embedding_model_chooser(
            model_provider=model_provider,
            model_reference=model_reference,
            api_key=api_key,
        )

        prowler_documents = extract_prowler_metadata_from_github(github_token)

        logger.info("Indexing the extracted metadata")
        index = VectorStoreIndex.from_documents(
            documents=prowler_documents, show_progress=True
        )
        logger.info("Persisting the indexed data in the vector store")
        index_folder_name = "indexed_data_db"
        index.storage_context.persist(join(vector_store_path, index_folder_name))

        metadata = {
            "date_of_creation": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "model_provider": model_provider,
            "model_reference": model_reference,  # TODO: Change this to write the key of the model instead the value. Should be "text-embedding-004" instead of "models/text-embedding-004"
        }

        with open(
            join(vector_store_path, index_folder_name, "index_metadata.json"), "w"
        ) as metadata_file:
            json.dump(metadata, metadata_file)
    except Exception as e:
        logger.exception(f"An error occurred while building the RAG dataset: {e}")
        raise e
