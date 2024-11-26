import json
import os
from typing import List

from llama_index.core import StorageContext, load_index_from_storage
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.settings import Settings

from core.src.utils.model_chooser import embedding_model_chooser


def get_relevant_reference_checks(
    security_analysis: str, check_provider: str, check_service: str
) -> List[str]:
    """Get relevant existing checks based on check description.

    This function retrieves relevant checks by loading indexed metadata and using a retriever
    to find nodes that match the given security analysis. It then filters these nodes based on
    the specified check provider and check service.
    Args:
        security_analysis: The security analysis string to be used for retrieving relevant checks.
        check_provider: The provider of the checks to filter the results.
        check_service: The service of the checks to filter the results.
    Returns:
        A list of relevant check names that match the given criteria.
    Raises:
        ValueError: If the indexed data for retrieval is not available.
    """

    relevant_checks = []

    indexed_data_db = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "../../indexed_data_db"
    )

    if os.path.exists(indexed_data_db):
        with open(os.path.join(indexed_data_db, "index_metadata.json"), "r") as f:
            index_metadata = json.load(f)

        Settings.embed_model = embedding_model_chooser(
            model_provider=index_metadata.get("model_provider", ""),
            model_reference=index_metadata.get("model_reference", ""),
        )

        # Retrieve the indexed data
        storage_context = StorageContext.from_defaults(persist_dir=indexed_data_db)

        index = load_index_from_storage(storage_context)

        retriever = index.as_retriever(similarity_top_k=5)

        nodes = retriever.retrieve(security_analysis)

        # Post-process the nodes to get the relevant checks

        filtered_nodes = SimilarityPostprocessor(
            similarity_cutoff=0.75
        ).postprocess_nodes(nodes)

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

    else:
        raise ValueError("Indexed data for RAG is not available")

    return relevant_checks
