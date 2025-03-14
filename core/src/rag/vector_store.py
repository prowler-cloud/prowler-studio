import base64
import gzip
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from llama_index.core import (
    Settings,
    StorageContext,
    VectorStoreIndex,
    load_index_from_storage,
)
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.query_engine.retriever_query_engine import RetrieverQueryEngine
from llama_index.core.schema import Document
from loguru import logger

from core.src.utils.model_chooser import embedding_model_chooser


def read_file(file_path: Path, json_load: bool = False) -> Union[str, dict]:
    """
    Safely reads file content, returning an empty string or dictionary if the file doesn't exist.

    Args:
        file_path: Path to the file to read.
        json_load: If True, attempts to load the file content as JSON. Defaults to False.

    Returns:
        The content of the file (string or dictionary) or an empty string/dictionary if the file doesn't exist.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If json_load is True and the file content is not valid JSON.
    """
    if file_path.exists():
        with open(file_path, "r") as f:
            content = f.read()
            if json_load:
                try:
                    return json.loads(content)
                except json.JSONDecodeError as e:
                    raise json.JSONDecodeError(
                        f"Invalid JSON in file {file_path}: {e.msg}", e.doc, e.pos
                    ) from e
            else:
                return content
    else:
        raise FileNotFoundError(f"File {file_path} not found.")


####################################################################################################


class CheckInventory:
    """Manages the code and metadata of checks and services associated with an index of checks.

    Attributes:
        _check_inventory (dict): Inventory of checks and services. Nested dictionary with the following structure:
            {
                "provider_name": {
                    "service_name": {
                        "description": str,
                        "code": str,
                        "checks": {
                            "check_id": {
                                "metadata": str,
                                "code": str,
                                "fixer": str
                            },
                            ...
                        }
                    },
                    ...
                },
                ...
            }
    """

    def __init__(self, metadata: dict = {}):
        self._check_inventory = metadata.get("check_inventory", {})

    def to_dict(self):
        """Returns the inventory as a dictionary."""
        return self._check_inventory

    def get_available_providers(self) -> set[str]:
        """Retrieve the available providers.

        Returns:
            A set of available providers.
        """
        return set(self.check_inventory.keys())

    def get_available_services_in_provider(self, provider_name: str) -> set[str]:
        """Retrieve the available services for a given provider.

        Args:
            provider_name: The Prowler provider.

        Returns:
            A set of available services for the provider.
        """
        return set(self.check_inventory.get(provider_name, {}).keys())

    def get_available_checks_in_service(
        self, provider_name: str, service_name: str
    ) -> set[str]:
        """Retrieve the available checks for a given provider and service.

        Args:
            provider_name: The Prowler provider.
            service_name: The service name.

        Returns:
            A set of available checks for the provider and service.
        """
        return set(
            self.check_inventory.get(provider_name, {})
            .get(service_name, {})
            .get("checks", {})
            .keys()
        )

    def update_service(self, service_dir: Path) -> bool:
        """Update the service code in the check inventory.

        If the service does not exist in the inventory, it will be added. If the service already exists,
        it will be updated only if the service code is different.

        Args:
            service_dir: Directory where the service is located.

        Returns:
            True if the service was updated, False otherwise.
        """
        provider = service_dir.parent.parent.name
        service = service_dir.name

        self._check_inventory.setdefault(provider, {}).setdefault(
            service, {"description": "", "code": "", "checks": {}}
        )

        updated = False
        service_file_path = service_dir / f"{service}_service.py"

        if service_file_path.exists():
            repo_service_code = read_file(service_file_path)

            if repo_service_code != self.get_service_code(provider, service):
                self._check_inventory[provider][service]["code"] = (
                    self._prepare_data_for_storage(repo_service_code)
                )
                updated = True

        return updated

    def get_service_code(self, provider: str, service: str) -> str:
        """Retrieve the code of a service.

        Args:
            provider: The Prowler provider.
            service: The service name.

        Returns:
            The code of the service.
        """
        return self._get_data_format_for_storage(
            self._check_inventory.get(provider, {}).get(service, {}).get("code", "")
        )

    def get_check_metadata(self, provider: str, service: str, check_id: str) -> dict:
        """Retrieve the metadata of a check.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The check ID.

        Returns:
            The metadata of the check.
        """
        metadata_str = self._get_data_format_for_storage(
            self._check_inventory.get(provider, {})
            .get(service, {})
            .get("checks", {})
            .get(check_id, {})
            .get("metadata", "")
        )
        if metadata_str != "":
            return json.loads(metadata_str)
        else:
            return {}

    def get_check_code(self, provider: str, service: str, check_id: str) -> str:
        """Retrieve the code of a check.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The check ID.

        Returns:
            The code of the check.
        """
        return self._get_data_format_for_storage(
            self._check_inventory.get(provider, {})
            .get(service, {})
            .get("checks", {})
            .get(check_id, {})
            .get("code", "")
        )

    def get_check_fixer(self, provider: str, service: str, check_id: str) -> str:
        """Retrieve the fixer of a check.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The check ID.

        Returns:
            The fixer of the check.
        """
        return self._get_data_format_for_storage(
            self._check_inventory.get(provider, {})
            .get(service, {})
            .get("checks", {})
            .get(check_id, {})
            .get("fixer", "")
        )

    def update_check_metadata(self, provider, service, check_id, file_path) -> bool:
        """Update the metadata of a check.

        Args:
            provider: The Prowler provider of the check.
            service: The service name.
            check_id: The ID of the check.
            file_path: Path to the file containing the metadata.

        Returns:
            True if the metadata was updated, False otherwise.
        """
        if file_path.exists():
            repo_content = read_file(file_path, json_load=True)
            if repo_content != self.get_check_metadata(provider, service, check_id):
                self._check_inventory[provider][service]["checks"][check_id][
                    "metadata"
                ] = self._prepare_data_for_storage(json.dumps(repo_content))
                return True
        return False

    def update_check_code(self, provider, service, check_id, file_path) -> bool:
        """Update the code of a check.

        Args:
            provider: The Prowler provider of the check.
            service: The service name.
            check_id: The ID of the check.
            file_path: Path to the file containing the code.

        Returns:
            True if the code was updated, False otherwise.
        """
        if file_path.exists():
            repo_content = read_file(file_path)
            if repo_content != self.get_check_code(provider, service, check_id):
                self._check_inventory[provider][service]["checks"][check_id]["code"] = (
                    self._prepare_data_for_storage(repo_content)
                )
                return True
        return False

    def update_check_fixer(self, provider, service, check_id, file_path) -> bool:
        """Update the fixer of a check.

        Args:
            provider: The Prowler provider of the check.
            service: The service name.
            check_id: The ID of the check.
            file_path: Path to the file containing the fixer.

        Returns:
            True if the fixer was updated, False otherwise.
        """
        if file_path.exists():
            repo_content = read_file(file_path)
            if repo_content != self.get_check_fixer(provider, service, check_id):
                self._check_inventory[provider][service]["checks"][check_id][
                    "fixer"
                ] = self._prepare_data_for_storage(repo_content)
                return True
        return False

    # Storage format functions

    def _prepare_data_for_storage(self, data: str) -> str:
        """Compress and encode data for storage.

        Args:
            data: The data to compress and encode.

        Returns:
            The compressed and encoded data.
        """
        try:
            return base64.b64encode(gzip.compress(data.encode())).decode()
        except Exception as e:
            raise Exception(f"Error preparing data for storage: {e}")

    def _get_data_format_for_storage(self, data: str) -> str:
        """Decompress and decode data for storage.

        Args:
            data: The data to decompress and decode.

        Returns:
            The decompressed and decoded data.
        """
        try:
            return gzip.decompress(base64.b64decode(data)).decode()
        except Exception as e:
            raise Exception(f"Error getting data format for storage: {e}")


####################################################################################################


class CheckMetadataVectorStore:
    """Manages the indexing and retrieval of check metadata

    Constants:
        INDEX_METADATA_NAME (str): Name of the index metadata file.
        DEFAULT_STORE_DIR (Path): Default path to the vector store.

    Attributes:
        _embedding_model_provider (str): Name of the embedding model provider.
        _embedding_model_reference (str): Reference of the embedding model.
        _index (VectorStoreIndex | None): Index of the check metadata.
        check_inventory (CheckInventory): Inventory of checks and services.
        _creation_date (str): Date when the index was created.
        _last_updated (str | None): Date when the index was last updated.
    """

    INDEX_METADATA_NAME = "db_metadata.json"
    DEFAULT_STORE_DIR = (
        Path(__file__).resolve().parent.parent.parent / "indexed_check_metadata_db"
    )

    def __init__(
        self,
        embedding_model_provider: Optional[str] = None,
        embedding_model_reference: Optional[str] = None,
        model_api_key: Optional[str] = None,
    ):
        """
        Initializes the CheckMetadataVectorStore object.

        Args:
            embedding_model_provider: Name of the embedding model provider.
            embedding_model_reference: Reference of the embedding model.
            model_api_key: API key to access the embedding model.
        """
        metadata_path = self.DEFAULT_STORE_DIR / self.INDEX_METADATA_NAME

        if metadata_path.exists():
            self._load_existing_index(metadata_path, model_api_key)
        else:
            if not embedding_model_provider or not embedding_model_reference:
                raise ValueError(
                    "You must provide the embedding model provider and reference to create a new index."
                )
            else:
                self._initialize_embedding_model(
                    embedding_model_provider=embedding_model_provider,
                    embedding_model_reference=embedding_model_reference,
                    model_api_key=model_api_key,
                )
                self._index = None
                self.check_inventory = CheckInventory()
                self._creation_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._last_updated = None

    def build_check_vector_store(
        self,
        prowler_directory_path: Path,
        overwrite: bool = False,
    ) -> None:
        """
        Builds the vector store and saves it to disk.

        Args:
            prowler_directory_path: Path to the Prowler directory.
            overwrite: Whether to overwrite the existing index in the vector store.
        """

        try:
            if self._index is not None and not overwrite:
                raise Exception(
                    "An index already exists in the vector store. Set the 'overwrite' parameter to True to update the existing index."
                )
            else:
                to_insert_documents = self._load_updated_checks_from_local_repo(
                    prowler_directory_path
                )

                if self._index is not None and overwrite and to_insert_documents:
                    for document in to_insert_documents:
                        self._index.update_ref_doc(document)
                elif self._index is None:
                    self._index = VectorStoreIndex.from_documents(
                        documents=to_insert_documents, show_progress=True
                    )

                self._store_index_in_disk(
                    overwrite_with_other_model=overwrite,
                )
        except Exception as e:
            raise Exception(f"Error building vector store: {e}")

    def get_related_checks(
        self,
        check_description: str,
        num_checks: int = 5,
        confidence_threshold: float = 0.75,
    ) -> dict[str, list[str]]:
        """Finds related checks based on the check description.

        Args:
            check_description: Description of the check.
            num_checks: Number of checks to return.
            confidence_threshold: Confidence threshold for the related checks.

        Returns:
            A dictionary of related checks grouped by provider and service.

        Raises:
            Exception: If an error occurs while retrieving the related checks.
        """
        try:
            check_retriever = self._index.as_retriever(similarity_top_k=num_checks)

            nodes = check_retriever.retrieve(check_description)
            filtered_nodes = SimilarityPostprocessor(
                similarity_cutoff=confidence_threshold
            ).postprocess_nodes(nodes)

            related_checks = {}

            for node in filtered_nodes:
                node_provider = node.metadata.get("provider", "")
                node_service = node.metadata.get("service_name", "")
                check_id = node.metadata.get("check_id", "")

                related_checks.setdefault(node_provider, {}).setdefault(
                    node_service, []
                ).append(check_id)

            return related_checks
        except Exception as e:
            raise Exception(f"Error retrieving related checks: {e}")

    def check_exists(self, check_description: str, confidence_threshold: float = 0.75):
        """Check if a check description exists, using retrieved nodes if available.

        Args:
            check_description: The description of the check.
            confidence_threshold: Confidence threshold for the check.
        Returns:
            True if the check exists, False otherwise.
        """
        query_engine = RetrieverQueryEngine.from_args(
            self._index.as_retriever(),
            node_postprocessors=[
                SimilarityPostprocessor(similarity_cutoff=confidence_threshold)
            ],
        )
        response = query_engine.query(
            f"SYSTEM CONTEXT: Prowler is an open-source CSPM tool. You have as context all checks metadata. A check metadata refers to the information related to a security automated control to ensure that best practices are followed, such as its description, provider, service, etc.\n Based in all current Prowler checks ensure if one or more checks metadata are covering the following description. You MUST answer with 'yes' or 'no', if the answer is 'no' please indicate the reason why the check is not covered by other checks.\n Check description: {check_description}"
        )
        return response.response.strip().lower() == "yes"

    # Private methods

    def _load_existing_index(
        self, metadata_path: Path, model_api_key: Optional[str]
    ) -> None:
        """Loads an existing index from disk.

        Args:
            metadata_path: Path to the index metadata file.
            model_api_key: API key
        """
        metadata = read_file(file_path=metadata_path, json_load=True)

        self._initialize_embedding_model(
            embedding_model_provider=metadata["model_provider"],
            embedding_model_reference=metadata["model_reference"],
            model_api_key=model_api_key,
        )
        self.check_inventory = CheckInventory(metadata)
        self._index = load_index_from_storage(
            StorageContext.from_defaults(
                persist_dir=str(self.DEFAULT_STORE_DIR),
            )
        )
        self._creation_date = metadata.get("creation_date", "")
        self._last_updated = metadata.get("last_updated", None)

    def _initialize_embedding_model(
        self,
        embedding_model_provider: str,
        embedding_model_reference: str,
        model_api_key: Optional[str],
    ) -> None:
        """
        Initializes the embedding model.

        Args:
            model_provider: Name of the embedding model provider.
            model_reference: Reference of the embedding model.
            model_api_key: API key to access the embedding model.
        """
        try:
            Settings.embed_model = embedding_model_chooser(
                embedding_model_provider=embedding_model_provider,
                emebedding_model_reference=embedding_model_reference,
                api_key=model_api_key,
            )
            self._embedding_model_provider = embedding_model_provider
            self._embedding_model_reference = embedding_model_reference
        except ValueError as e:
            raise ValueError(f"Error initializing embedding model: {e}")

    def _load_updated_checks_from_local_repo(
        self, prowler_directory_path: Path
    ) -> list[Document]:
        """Extracts only updated checks from the Prowler directory and converts them to a list of Document objects.

        Args:
            prowler_directory_path: Base path to the Prowler directory.

        Returns:
            A list of Document objects containing the metadata of only updated checks.

        Raises:
            FileNotFoundError: If the providers directory does not exist.
        """
        logger.info("Extracting updated checks from Prowler directory...")
        providers_dir = prowler_directory_path / "prowler/providers"
        if not providers_dir.exists():
            raise FileNotFoundError(
                f"Prowler providers directory not found: {providers_dir}"
            )

        updated_documents = []
        for metadata_file in providers_dir.rglob("*.metadata.json"):
            self.check_inventory.update_service(metadata_file.parent.parent)
            self.check_inventory.update_check_code(
                provider=metadata_file.parents[3].name,
                service=metadata_file.parents[1].name,
                check_id=metadata_file.parent.name,
                file_path=metadata_file.parent / f"{metadata_file.parent.name}.py",
            )
            self.check_inventory.update_check_fixer(
                provider=metadata_file.parents[3].name,
                service=metadata_file.parents[1].name,
                check_id=metadata_file.parent.name,
                file_path=metadata_file.parent
                / f"{metadata_file.parent.name}_fixer.py",
            )

            # Only rebuild the document if the metadata was updated because the document is only composed of metadata data
            if self.check_inventory.update_check_metadata(
                provider=metadata_file.parents[3].name,
                service=metadata_file.parents[1].name,
                check_id=metadata_file.parent.name,
                file_path=metadata_file,
            ):
                document = self._create_check_document(check_dir=metadata_file.parent)
                updated_documents.append(document)

        return updated_documents

    def _create_check_document(self, check_dir: Path) -> Document:
        """Create LlamaIndex Document from check metadata.

        Args:
            check_dir: Directory where the check is located.

        Returns:
            A Document object containing the metadata extracted from the metadata file.
        """
        metadata = read_file(
            file_path=(check_dir / f"{check_dir.name}.metadata.json"), json_load=True
        )

        # Make relevant text fields searchable (Provider, CheckID, CheckTitle, ServiceName, Severity, Description, Risk, Notes)
        metadata_formatted = f"The check '{metadata['CheckID']}' titled '{metadata['CheckTitle']}' applies to the '{metadata['ServiceName']}' service in the provider '{metadata['Provider']}'. It has a severity of '{metadata['Severity']}'\n The description states: '{metadata['Description']}' The risk is '{metadata['Risk']}' Additional notes: '{metadata['Notes']}'"

        document = Document(
            id_=f"{metadata['Provider']}_{metadata['CheckID']}",
            text=metadata_formatted,
            metadata={
                "provider": metadata["Provider"],
                "service_name": metadata["ServiceName"],
                "check_id": metadata["CheckID"],
                "severity": metadata["Severity"],
                "resource_type": metadata["ResourceType"],
                "categories": ", ".join(metadata["Categories"]),
            },
        )

        return document

    def _store_index_in_disk(
        self,
        overwrite_with_other_model: bool = False,
    ) -> None:
        """Stores the index to disk.

        Args:
            vector_store_path: Path to store the index.
        """
        logger.info("Storing index in disk...")
        try:
            store_index_metadata = {
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "model_provider": self._embedding_model_provider,
                "model_reference": self._embedding_model_reference,
                "check_inventory": self.check_inventory.to_dict(),
            }

            if self.DEFAULT_STORE_DIR.exists():
                # Load the past configuration
                with open(
                    self.DEFAULT_STORE_DIR / self.INDEX_METADATA_NAME, "r"
                ) as metadata_file:
                    store_index_metadata = json.load(metadata_file)

                if (
                    self._embedding_model_reference
                    != store_index_metadata["model_reference"]
                ):
                    if overwrite_with_other_model:
                        logger.warning(
                            f"The model reference has changed. Overwriting the index with the new model: {self._embedding_model_reference}"
                        )
                        store_index_metadata["model_reference"] = (
                            self._embedding_model_reference
                        )
                        store_index_metadata["creation_date"] = datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    else:
                        raise Exception(
                            "The model reference has changed. Please set the 'overwrite_with_other_model' parameter to True to overwrite the index with the new model reference."
                        )
            else:
                store_index_metadata["creation_date"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            self._index.storage_context.persist(self.DEFAULT_STORE_DIR)
            # Persist some metadata and check inventory
            with open(
                self.DEFAULT_STORE_DIR / self.INDEX_METADATA_NAME, "w"
            ) as metadata_file:
                json.dump(
                    store_index_metadata,
                    metadata_file,
                )
        except Exception as e:
            raise Exception(f"Error storing index in disk: {e}")
