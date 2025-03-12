import base64
import gzip
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

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


class CheckMetadataVectorStore:
    _INDEX_METADATA_NAME = "index_metadata.json"
    _DEFAULT_STORE_DIR = (
        Path(__file__).resolve().parent.parent.parent / "indexed_data_db"
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
        self._index = None
        self._check_inventory = {}
        self._embedding_model_provider = None
        self._embedding_model_reference = None

        metadata_path = self._DEFAULT_STORE_DIR / self._INDEX_METADATA_NAME

        if metadata_path.exists():
            self._load_existing_index(metadata_path, model_api_key)
        else:
            self._initialize_new_index(
                embedding_model_provider, embedding_model_reference, model_api_key
            )

    def build_check_vector_store(
        self,
        prowler_directory_path: str,
        vector_store_path: Optional[str] = os.path.abspath(
            os.path.join(__file__, "../../../")
        ),
        overwrite: bool = False,
    ) -> None:
        """
        Builds the vector store and saves it to disk.

        Args:
            prowler_directory_path: Path to the Prowler directory.
            vector_store_path: Path to store the vector store.
            overwrite: Whether to overwrite the existing index in the vector store.
        """
        if self._index is not None and not overwrite:
            raise Exception(
                "An index already exists in the vector store. Set the 'overwrite' parameter to True to overwrite the existing index."
            )

        try:
            documents = self._load_checks_from_local_repo(prowler_directory_path)
            self._index_documents(documents)
            self._store_index_in_disk(
                vector_store_path=vector_store_path,
                overwrite_with_other_model=overwrite,
            )
        except Exception as e:
            raise Exception(f"Error building vector store: {e}")

    def get_service_code(self, provider_name: str, service_name: str) -> str:
        """Retrieve the code for a given service.

        Args:
            provider_name: The Prowler provider of the service.
            service_name: The name of the service.

        Returns:
            The code of the service if found, otherwise raises a ValueError.

        Raises:
            ValueError: If an error occurs while retrieving the service code.
        """
        try:
            return gzip.decompress(
                base64.b64decode(
                    self._check_inventory[provider_name][service_name]["code"]
                )
            ).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Error retrieving service {service_name} code: {e}")

    def get_check_metadata(self, provider_name: str, check_id: str) -> dict:
        """Retrieve metadata for a given check ID.

        Args:
            provider_name: The Prowler provider of the check.
            check_id: The ID of the check.

        Returns:
            The metadata of the check if found, otherwise raises a ValueError.

        Raises:
            ValueError: If an error occurs while retrieving the check metadata.
        """
        try:
            return json.loads(
                gzip.decompress(
                    base64.b64decode(
                        self._check_inventory[provider_name][check_id.split("_")[0]][
                            "checks"
                        ][check_id]["metadata"]
                    )
                ).decode("utf-8")
            )

        except KeyError as e:
            raise ValueError(
                f"Check {check_id} not found for provider {provider_name}: {e}"
            )
        except Exception as e:
            raise ValueError(
                f"Error retrieving check metadata {check_id} for provider {provider_name}: {e}"
            )

    def get_check_code(self, provider_name: str, check_id: str) -> str:
        """Retrieve code for a given check ID.

        Args:
            provider_name: The Prowler provider of the check.
            check_id: The ID of the check.

        Returns:
            The code of the check if found, otherwise raises a ValueError.

        Raises:
            ValueError: If an error occurs while retrieving the check code.
        """
        try:
            return gzip.decompress(
                base64.b64decode(
                    self._check_inventory[provider_name][check_id.split("_")[0]][
                        "checks"
                    ][check_id]["code"]
                )
            ).decode("utf-8")
        except Exception as e:
            raise ValueError(
                f"Error retrieving check code {check_id} for provider {provider_name}: {e}"
            )

    def get_check_fixer(self, provider_name: str, check_id: str) -> str:
        """Retrieve fixer for a given check ID.

        Args:
            provider_name: The Prowler provider of the check.
            check_id: The ID of the check.

        Returns:
            The fixer of the check if found, otherwise raises a ValueError.

        Raises:
            ValueError: If an error occurs while retrieving the check fixer.
        """
        try:
            return gzip.decompress(
                base64.b64decode(
                    self._check_inventory[provider_name][check_id.split("_")[0]][
                        "checks"
                    ][check_id]["fixer"]
                )
            ).decode("utf-8")
        except Exception as e:
            raise ValueError(
                f"Error retrieving check fixer {check_id} for provider_name {provider_name}: {e}"
            )

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

    def get_available_providers(self) -> set[str]:
        """Retrieve the available providers.

        Returns:
            A set of available providers.
        """
        return set(self._check_inventory.keys())

    def get_available_services(self, provider_name: str) -> set[str]:
        """Retrieve the available services for a given provider.

        Args:
            provider_name: The Prowler provider.

        Returns:
            A set of available services for the provider.
        """
        return set(self._check_inventory.get(provider_name, {}).keys())

    def get_available_checks(self, provider_name: str, service_name: str) -> set[str]:
        """Retrieve the available checks for a given provider and service.

        Args:
            provider_name: The Prowler provider.
            service_name: The service name.

        Returns:
            A set of available checks for the provider and service.
        """
        return set(
            self._check_inventory.get(provider_name, {})
            .get(service_name, {})
            .get("checks", {})
            .keys()
        )

    # Private methods

    def _load_existing_index(
        self, metadata_path: str, model_api_key: Optional[str]
    ) -> None:
        """Loads an existing index from disk.

        Args:
            metadata_path: Path to the index metadata file.
            model_api_key: API key
        """
        metadata = self._read_json_file(metadata_path)

        self._initialize_embedding_model(
            embedding_model_provider=metadata["model_provider"],
            embedding_model_reference=metadata["model_reference"],
            model_api_key=model_api_key,
        )
        self._check_inventory = metadata["check_inventory"]
        self._index = load_index_from_storage(
            StorageContext.from_defaults(
                persist_dir=str(metadata_path.parent),
            )
        )

    def _initialize_new_index(
        self,
        embedding_model_provider: str,
        embedding_model_reference: str,
        model_api_key: Optional[str],
    ) -> None:
        """Initializes a new index.

        Args:
            embedding_model_provider: Name of the embedding model provider.
            embedding_model_reference: Reference of the embedding model.
            model_api_key: API key to access the embedding model.
        """
        if not embedding_model_provider or not embedding_model_reference:
            raise ValueError(
                "Please provide an embedding model provider and reference to initialize the CheckMetadataVectorStore."
            )

        self._initialize_embedding_model(
            embedding_model_provider=embedding_model_provider,
            embedding_model_reference=embedding_model_reference,
            model_api_key=model_api_key,
        )

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

    def _load_checks_from_local_repo(
        self, prowler_directory_path: str
    ) -> list[Document]:
        """
        Extracts all data needed from the Prowler directory and converts it to a list of Document objects.

        Args:
            prowler_directory_path: Base path to the Prowler directory.

        Returns:
            A list of Document objects containing the metadata extracted from the Prowler directory.

        Raises:
            FileNotFoundError: If the providers directory does not exist.
        """
        logger.info("Extracting checks from Prowler directory...")
        documents = []
        providers_path = os.path.join(prowler_directory_path, "prowler/providers")

        if not os.path.exists(providers_path):
            raise FileNotFoundError(f"Directory {providers_path} not found.")

        for root, _, files in os.walk(providers_path):
            for file in files:
                if file.endswith(".metadata.json"):
                    document = self._create_check_document(check_dir=root)
                    documents.append(document)
                    self._update_check_inventory(check_dir=root)

        return documents

    def _create_check_document(self, check_dir: str) -> Document:
        """Process a check to create a Document object and insert in the RAG knowledge base.

        Args:
            check_dir: Directory where the check is located.

        Returns:
            A Document object containing the metadata extracted from the metadata file.
        """
        metadata_path = os.path.join(
            check_dir, f"{check_dir.split('/')[-1]}.metadata.json"
        )

        metadata = self._read_json_file(metadata_path)

        # Make relevant text fields searchable (Provider, CheckID, CheckTitle, ServiceName, Severity, Description, Risk, Notes)
        metadata_formatted = f"The check '{metadata['CheckID']}' titled '{metadata['CheckTitle']}' applies to the '{metadata['ServiceName']}' service in the provider '{metadata['Provider']}'. It has a severity of '{metadata['Severity']}'\n The description states: '{metadata['Description']}' The risk is '{metadata['Risk']}' Additional notes: '{metadata['Notes']}'"

        document = Document(
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

    def _update_check_inventory(self, check_dir: str) -> None:
        """Update the check inventory with the check metadata, code, fixer and service code.

        Args:
            check_dir: Directory where the check is located.
        """
        check_id = check_dir.split("/")[-1]
        service = check_dir.split("/")[-2]
        provider = check_dir.split("/")[-4]

        # Initialize defaults values if not exists
        self._check_inventory.setdefault(provider, {}).setdefault(
            service, {"description": "", "code": "", "checks": {}}
        )["checks"].setdefault(check_id, {"metadata": {}, "code": "", "fixer": ""})

        # If service code from the inventory and the actual service code are different, update the inventory

        service_file_path = os.path.join(
            os.path.dirname(check_dir), f"{service}_service.py"
        )

        if os.path.exists(service_file_path):
            repo_service_code = self._read_file_content(service_file_path)

            if self._check_inventory[provider][service]["code"] != repo_service_code:
                self._check_inventory[provider][service]["code"] = base64.b64encode(
                    gzip.compress(repo_service_code.encode(encoding="utf-8"))
                ).decode("utf-8")

        # Update the check metadata, code and fixer
        self._check_inventory[provider][service]["checks"][check_id] = {
            "metadata": base64.b64encode(
                gzip.compress(
                    json.dumps(
                        self._read_json_file(
                            os.path.join(check_dir, f"{check_id}.metadata.json")
                        )
                    ).encode(encoding="utf-8")
                )
            ).decode("utf-8"),
            "code": base64.b64encode(
                gzip.compress(
                    self._read_file_content(
                        os.path.join(check_dir, f"{check_id}.py")
                    ).encode(encoding="utf-8")
                )
            ).decode("utf-8"),
            "fixer": (
                base64.b64encode(
                    gzip.compress(
                        self._read_file_content(
                            os.path.join(check_dir, f"{check_id}_fixer.py")
                        ).encode(encoding="utf-8")
                    )
                ).decode("utf-8")
                if os.path.exists(os.path.join(check_dir, f"{check_id}_fixer.py"))
                else ""
            ),
        }

    def _read_json_file(self, file_path: str) -> dict:
        """Safely read a JSON file, returning an empty dictionary if the file doesn't exist

        Args:
            file_path: Path to the JSON file to read.

        Returns:
            The content of the JSON file or an empty dictionary if the file doesn't exist.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return json.load(f)
        else:
            raise FileNotFoundError(f"File {file_path} not found.")

    def _read_file_content(self, file_path: str) -> str:
        """Safely read file content, returning empty string if file doesn't exist

        Args:
            file_path: Path to the file to read.

        Returns:
            The content of the file or an empty string if the file doesn't exist.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return f.read()
        else:
            raise FileNotFoundError(f"File {file_path} not found.")

    def _index_documents(self, documents: list[Document]) -> None:
        """
        Indexes the documents in the vector store.

        Args:
            documents: A list of Document objects to be indexed.
        """
        logger.info("Indexing documents...")
        try:
            self._index = VectorStoreIndex.from_documents(
                documents=documents, show_progress=True
            )
        except Exception as e:
            raise Exception(f"Error indexing documents: {e}")

    def _store_index_in_disk(
        self,
        vector_store_path: str = os.path.abspath(
            os.path.join(__file__, "../../../indexed_data_db")
        ),
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
                "check_inventory": self._check_inventory,
            }

            if os.path.exists(os.path.join(vector_store_path)):
                # Load the past configuration
                with open(
                    os.path.join(vector_store_path, "index_metadata.json"),
                    "r",
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

            self._index.storage_context.persist(os.path.join(vector_store_path))
            # Persist some metadata and check inventory
            with open(
                os.path.join(vector_store_path, "index_metadata.json"),
                "w",
            ) as metadata_file:
                json.dump(
                    store_index_metadata,
                    metadata_file,
                )
        except Exception as e:
            raise Exception(f"Error storing index in disk: {e}")
