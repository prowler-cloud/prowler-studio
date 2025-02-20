import json
import os
from datetime import datetime
from typing import Optional

from llama_index.core import Settings, StorageContext, VectorStoreIndex
from llama_index.core.schema import Document
from loguru import logger

from core.src.utils.model_chooser import embedding_model_chooser


class CheckMetadataVectorStore:
    def __init__(
        self,
        model_provider: Optional[str] = None,
        model_reference: Optional[str] = None,
        model_api_key: Optional[str] = None,
    ):
        """
        Initializes the CheckMetadataVectorStore object.

        Args:
            model_provider: Name of the embedding model provider.
            model_reference: Reference of the embedding model.
        """
        # Should contain a BaseIndex object
        self._index = None
        self._check_inventory = {}

        # Check if in there is an actual index in disk to be loaded
        if os.path.exists(
            os.path.join(
                os.path.abspath(os.path.join(__file__, "../../../")),
                "indexed_data_db/index_metadata.json",
            )
        ):
            with open(
                os.path.join(
                    os.path.abspath(os.path.join(__file__, "../../../")),
                    "indexed_data_db/index_metadata.json",
                ),
                "r",
            ) as metadata_file:
                store_index_metadata = json.load(metadata_file)
                self._initialize_embedding_model(
                    model_provider=store_index_metadata["model_provider"],
                    model_reference=store_index_metadata["model_reference"],
                    model_api_key=model_api_key,
                )
                self._check_inventory = store_index_metadata["check_inventory"]
                self._index = StorageContext.from_defaults(
                    persist_dir=os.path.abspath(
                        os.path.join(__file__, "../../../indexed_data_db")
                    )
                )
        else:
            # If not, check if the user provided the model_provider and model_reference
            if not model_provider or not model_reference:
                raise ValueError(
                    "Please provide a model provider and reference to initialize the CheckMetadataVectorStore."
                )
            else:
                self._initialize_embedding_model(
                    model_provider=model_provider,
                    model_reference=model_reference,
                    model_api_key=model_api_key,
                )

    def _initialize_embedding_model(
        self, model_provider: str, model_reference: str, model_api_key: Optional[str]
    ) -> None:
        """
        Initializes the embedding model.

        Args:
            model_provider: Name of the embedding model provider.
            model_reference: Reference of the embedding model.
            model_api_key: API key to access the embedding model.
        """
        logger.info("Initializing embedding model...")
        try:
            Settings.embed_model = embedding_model_chooser(
                model_provider=model_provider,
                model_reference=model_reference,
                api_key=model_api_key,
            )
            self._embedding_model_provider = model_provider
            self._embedding_model_reference = model_reference
        except ValueError as e:
            raise ValueError(f"Error initializing embedding model: {e}")

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
        if self._index and not overwrite:
            raise Exception(
                "An index already exists in the vector store. Set the 'overwrite' parameter to True to overwrite the existing index."
            )

        try:
            documents = self._load_check_metadata(prowler_directory_path)
            self._index_documents(documents)
            self._store_index_in_disk(
                vector_store_path=vector_store_path,
                overwrite_with_other_model=overwrite,
            )
        except Exception as e:
            raise Exception(f"Error building vector store: {e}")

    def _load_check_metadata(self, prowler_directory_path: str) -> list[Document]:
        """
        Extracts the metadata from the Prowler directory and converts it to a list of Document objects.

        Args:
            prowler_directory_path: Base path to the Prowler directory.

        Returns:
            A list of Document objects containing the metadata extracted from the Prowler directory.
        """
        logger.info("Extracting metadata from Prowler directory...")
        documents = []

        providers_path = os.path.join(prowler_directory_path, "prowler/providers")

        if os.path.exists(providers_path):
            for root, dirs, files in os.walk(providers_path):
                for file in files:
                    if file.endswith(".metadata.json"):
                        file_path = os.path.join(root, file)
                        with open(file_path, "r") as f:
                            metadata = json.load(f)
                            # Make relevant text fields searchable (Provider, CheckID, CheckTitle, ServiceName, Severity, Description, Risk, Notes)
                            metadata_formatted = f"The check '{metadata['CheckID']}' titled '{metadata['CheckTitle']}' applies to the '{metadata['ServiceName']}' service in the provider '{metadata['Provider']}'. It has a severity of '{metadata['Severity']}'\n The description states: '{metadata['Description']}' The risk is '{metadata['Risk']}' Additional notes: '{metadata['Notes']}'"
                            documents.append(
                                Document(
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
                            )
                            # Add the check_id to the inventory
                            self._check_inventory.setdefault(
                                metadata["Provider"], {}
                            ).setdefault(metadata["ServiceName"], []).append(
                                metadata["CheckID"]
                            )
        else:
            raise FileNotFoundError(f"Directory {providers_path} not found.")

        return documents

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
        """
        Stores the index to disk.

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
