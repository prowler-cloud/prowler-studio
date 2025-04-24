import json
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

from ..utils.model_chooser import embedding_model_chooser
from .check_inventory import CheckInventory
from .utils import read_file


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
        Path(__file__).resolve().parents[3] / "indexed_check_metadata_db"
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
        logger.info("Building check vector store...")
        try:
            if self._index is not None and not overwrite:
                raise Exception(
                    "An index already exists in the vector store. Set the 'overwrite' parameter to True to update the existing index."
                )
            else:
                to_insert_documents = self._load_updated_checks_from_local_repo(
                    prowler_directory_path
                )

                to_delete_documents = self._load_deleted_checks_from_local_repo(
                    prowler_directory_path
                )

                if (
                    self._index is not None
                    and overwrite
                    and (to_insert_documents or to_delete_documents)
                ):
                    for document in to_insert_documents:
                        if document.id_ in self._index.ref_doc_info:
                            self._index.update_ref_doc(document)
                        else:
                            self._index.insert(document)

                    for document_id in to_delete_documents:
                        if document_id in self._index.ref_doc_info:
                            self._index.delete_ref_doc(
                                document_id, delete_from_docstore=True
                            )

                elif self._index is None:
                    self._index = VectorStoreIndex.from_documents(
                        documents=to_insert_documents, show_progress=True
                    )

                self._store_index_in_disk()
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
            f"SYSTEM CONTEXT: Prowler is an open-source CSPM tool. You have as context all checks metadata. A check metadata refers to the information related to a security automated control to ensure that best practices are followed, such as its description, provider, service, etc.\n Based in all current Prowler checks ensure if one or more checks metadata are covering the following description. You MUST answer with 'yes' or 'no'.\n Check description: {check_description}"
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
        This method alse updates the check inventory with the metadata of the updated checks.

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

        for provider in providers_dir.rglob("*_provider.py"):
            provider_name = provider.name.split("_")[0]

            if provider not in self.check_inventory.get_available_providers():
                self.check_inventory.add_provider(provider_name)

            for service in provider.parent.rglob("*_service.py"):
                service_name = service.name.split("_")[0]

                self.check_inventory.update_service(
                    file_path=service,
                )

                for check_metadata_file in service.parent.rglob("*.metadata.json"):
                    check_id = check_metadata_file.parent.name

                    self.check_inventory.update_check_code(
                        provider=provider_name,
                        service=service_name,
                        check_id=check_id,
                        file_path=check_metadata_file.parent / f"{check_id}.py",
                    )
                    self.check_inventory.update_check_fixer(
                        provider=provider_name,
                        service=service_name,
                        check_id=check_id,
                        file_path=check_metadata_file.parent / f"{check_id}_fixer.py",
                    )
                    # Only rebuild the document if the metadata was updated because the document is only composed of metadata data
                    if self.check_inventory.update_check_metadata(
                        provider=provider_name,
                        service=service_name,
                        check_id=check_id,
                        file_path=check_metadata_file,
                    ):
                        document = self._create_check_document(
                            check_dir=check_metadata_file.parent
                        )
                        updated_documents.append(document)

        return updated_documents

    def _load_deleted_checks_from_local_repo(
        self, prowler_directory_path: Path
    ) -> list[str]:
        """Extracts deleted checks from the Prowler directory and converts them to a list of document IDs.
        This method also updates the check inventory deleting the providers, services or checks that were deleted in the Prowler repo.

        Args:
            prowler_directory_path: Base path to the Prowler directory.

        Returns:
            A list of Document objects containing the metadata of deleted checks.
        """
        logger.info("Extracting deleted checks from Prowler directory...")

        # Recorer el inventario de checks y eliminar los checks que no existen en el repo
        deleted_checks = []
        for provider in self.check_inventory.get_available_providers():
            provider_path = prowler_directory_path / "prowler/providers" / f"{provider}"
            if not provider_path.exists():
                # Before deleting the provider is needed to get all the checks and add to the deleted checks list
                for service in self.check_inventory.get_available_services_in_provider(
                    provider_name=provider
                ):
                    for (
                        check_id
                    ) in self.check_inventory.get_available_checks_in_service(
                        provider_name=provider, service_name=service
                    ):
                        deleted_checks.append(f"{provider}_{check_id}")
                self.check_inventory.delete_provider(provider)
            else:
                for service in self.check_inventory.get_available_services_in_provider(
                    provider_name=provider
                ):
                    service_path = (
                        prowler_directory_path
                        / "prowler/providers"
                        / provider
                        / "services"
                        / service
                    )
                    if not service_path.exists():
                        # Before deleting the service is needed to get all the checks and add to the deleted checks list
                        for (
                            check_id
                        ) in self.check_inventory.get_available_checks_in_service(
                            provider_name=provider, service_name=service
                        ):
                            deleted_checks.append(f"{provider}_{check_id}")
                        self.check_inventory.delete_service(provider, service)
                    else:
                        for (
                            check_id
                        ) in self.check_inventory.get_available_checks_in_service(
                            provider_name=provider, service_name=service
                        ):
                            check_path = (
                                prowler_directory_path
                                / "prowler/providers"
                                / provider
                                / "services"
                                / service
                                / check_id
                            )
                            if not check_path.exists():
                                deleted_checks.append(f"{provider}_{check_id}")
                                self.check_inventory.delete_check(
                                    provider=provider, check_id=check_id
                                )

        return deleted_checks

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

    def _store_index_in_disk(self) -> None:
        """Stores the index to disk.

        Args:
            vector_store_path: Path to store the index.
        """
        logger.info("Storing index in disk...")
        try:
            store_index_metadata = {
                "creation_date": self._creation_date,
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "model_provider": self._embedding_model_provider,
                "model_reference": self._embedding_model_reference,
                "check_inventory": self.check_inventory.to_dict(),
            }

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
