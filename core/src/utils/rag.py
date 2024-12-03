import json
import os
from typing import Dict, List, Optional

from llama_index.core import StorageContext, load_index_from_storage
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.query_engine.retriever_query_engine import RetrieverQueryEngine
from llama_index.core.settings import Settings

from core.src.utils.model_chooser import embedding_model_chooser


class IndexedDataManager:
    """Manager for loading and interacting with indexed data."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "../../indexed_data_db"
        )
        self.index_metadata = self._load_metadata()
        self.storage_context = self._initialize_storage_context()

    def _load_metadata(self) -> Dict[str, str]:
        """Load metadata from the indexed data directory.

        Returns:
            A dictionary containing the metadata of the indexed data.
        """
        metadata_path = os.path.join(self.base_dir, "index_metadata.json")
        if not os.path.exists(metadata_path):
            raise ValueError("Indexed metadata file not found.")
        with open(metadata_path, "r") as f:
            return json.load(f)

    def _initialize_storage_context(self) -> StorageContext:
        """Initialize and return the storage context.

        Returns:
            Default storage context for the indexed data.
        """
        Settings.embed_model = embedding_model_chooser(
            model_provider=self.index_metadata.get("model_provider", ""),
            model_reference=self.index_metadata.get("model_reference", ""),
        )
        return StorageContext.from_defaults(persist_dir=self.base_dir)

    def get_index(self):
        """Load the index from storage."""
        return load_index_from_storage(self.storage_context)


class CheckDataManager:
    """Manager for interacting with indexed checks data."""

    def __init__(
        self,
        indexed_data_manager: IndexedDataManager,
        similarity_top_k: int = 5,
        similarity_cutoff: float = 0.75,
    ):
        self.index = indexed_data_manager.get_index()
        self.retriever = self.index.as_retriever(similarity_top_k=similarity_top_k)
        self.nodes_postprocessor = SimilarityPostprocessor(
            similarity_cutoff=similarity_cutoff
        )
        self.query_engine = RetrieverQueryEngine.from_args(
            self.retriever, node_postprocessors=[self.nodes_postprocessor]
        )

    def get_relevant_checks(
        self, security_analysis: str, check_provider: str, check_service: str
    ) -> List[str]:
        """Retrieve relevant checks based on analysis, provider, and service.

        Args:
            security_analysis: The security analysis context.
            check_provider: The provider of the check.
            check_service: The service of the check.
        Returns:
            A list of relevant check names.
        """
        nodes = self.retriever.retrieve(security_analysis)
        filtered_nodes = SimilarityPostprocessor(
            similarity_cutoff=0.75
        ).postprocess_nodes(nodes)

        relevant_checks = []
        # TODO: Make this provider/service filter a propper PostProcessor class and use it here and in the query engine
        for node in filtered_nodes:
            node_provider = (
                node.metadata.get("file_path", "").split("/")[2]
                if len(node.metadata.get("file_path", "").split("/")) > 2
                else ""
            )
            node_service = node.metadata.get("file_name", "").split("_")[0]

            if node_provider == check_provider and node_service == check_service:
                relevant_checks.append(
                    node.metadata.get("file_name", "").replace(".metadata.json", "")
                )

        return relevant_checks

    def check_exists(self, check_description: str) -> bool:
        """Check if a check description exists, using retrieved nodes if available.

        Args:
            check_description: The description of the check.
        Returns:
            True if the check exists, False otherwise.
        """

        # Fallback to querying if no nodes are provided
        query_prompt = (
            f"SYSTEM CONTEXT: Prowler is an open-source CSPM tool. You have as context all checks metadata. "
            f"A check metadata refers to the information related to a security automated control to ensure that best "
            f"practices are followed, such as its description, provider, service, etc. With this information, please "
            f"ensure if a check with the following description already exists in the indexed data. You MUST answer with 'yes' or 'no': {check_description}"
        )
        response = self.query_engine.query(query_prompt)
        return response.response.strip().lower() == "yes"
