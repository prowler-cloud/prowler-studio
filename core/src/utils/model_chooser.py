import os
from typing import Optional

from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.llms.llm import LLM
from llama_index.embeddings.gemini import GeminiEmbedding
from llama_index.llms.gemini import Gemini
from llama_index.llms.gemini.base import GEMINI_MODELS
from llama_index.llms.llama_cpp import LlamaCPP

GEMINI_MODEL_NAMES = {
    "1.5 Flash": "models/gemini-1.5-flash",
}

SUPPORTED_LLMS = {"gemini": list(GEMINI_MODEL_NAMES.keys())}

GEMINI_EMBEDDING_MODELS_NAMES = {
    "text-embedding-004": "models/text-embedding-004",
}

SUPPORTED_EMBEDDING_MODELS = {"gemini": list(GEMINI_EMBEDDING_MODELS_NAMES.keys())}


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

    if model_provider == "llama_cpp":
        if model_reference.startswith("https://"):
            llm = LlamaCPP(
                model_url=model_reference,
                model_path=None,
                temperature=0.6,
                verbose=False,
            )
        elif os.path.exists(model_reference):
            llm = LlamaCPP(
                model_url=None,
                model_path=model_reference,
                temperature=0.6,
                verbose=False,
            )
        else:
            raise ValueError(f"LlamaCPP model {model_reference} not found.")
    elif model_provider == "gemini":
        if model_reference in SUPPORTED_LLMS[model_provider]:

            if not api_key:
                api_key = os.getenv("GOOGLE_API_KEY")

            llm = Gemini(
                model=GEMINI_MODEL_NAMES[model_reference],
                api_key=api_key,
            )
        else:
            raise ValueError(
                f"Model {model_reference} not supported by Gemini. The supported models are: {", ".join([model for model in GEMINI_MODELS if model.startswith('models')])}."
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
        embedding_model = GeminiEmbedding(
            model_name=GEMINI_EMBEDDING_MODELS_NAMES[model_reference],
            api_key=api_key,
        )
    else:
        raise ValueError(f"Model provider {model_provider} not supported.")

    return embedding_model
