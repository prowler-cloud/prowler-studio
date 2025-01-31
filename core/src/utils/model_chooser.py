import os
from typing import Optional

from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.llms.llm import LLM
from llama_index.embeddings.gemini import GeminiEmbedding
from llama_index.llms.gemini import Gemini

SUPPORTED_LLMS = {"gemini": ["models/gemini-1.5-flash"]}

SUPPORTED_EMBEDDING_MODELS = {"gemini": ["models/text-embedding-004"]}


def llm_chooser(
    model_provider: str, model_reference: str, api_key: Optional[str] = ""
) -> LLM:
    """Choose the right LLM model based on the user input.

    Args:
        model_provider: Provider of the LLM model.
        model_reference: Reference to the LLM model, depending on the provider it can be a name, a path or a URL.
        api_key: API key to access the model. It is not a required parameter if the model provider does not require it.
    Returns:
        The LLM model to use for the passed model provider and reference.
    """

    llm = None

    if model_provider == "gemini":
        if model_reference in SUPPORTED_LLMS[model_provider]:
            if not api_key:
                api_key = os.getenv("GOOGLE_API_KEY")

            llm = Gemini(
                model=model_reference,
                api_key=api_key,
            )
        else:
            raise ValueError(
                f"Model {model_reference} not supported by Gemini. The supported models are: {SUPPORTED_LLMS[model_provider]}"
            )
    else:
        raise ValueError(f"Model provider {model_provider} not supported.")

    return llm


def embedding_model_chooser(
    model_provider: str, model_reference: str, api_key: Optional[str] = ""
) -> BaseEmbedding:
    """Choose the right embedding model based on the user input.

    Args:
        model_provider: Provider of the embedding model.
        model_reference: Reference to the embedding model, depending on the provider it can be a name, a path or a URL.
        api_key: API key to access the model. It is not a required parameter if the model provider does not require it.
    Returns:
        The embedding model to use for the passed model provider and reference.
    """

    embedding_model = None

    if model_provider == "gemini":
        if model_reference in SUPPORTED_EMBEDDING_MODELS[model_provider]:
            if not api_key:
                api_key = os.getenv("GOOGLE_API_KEY")

            embedding_model = GeminiEmbedding(
                model_name=model_reference,
                api_key=api_key,
            )
    else:
        raise ValueError(f"Model provider {model_provider} not supported.")

    return embedding_model
