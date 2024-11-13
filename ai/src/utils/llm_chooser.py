from os.path import exists

from llama_index.core.llms.llm import LLM
from llama_index.llms.gemini import Gemini
from llama_index.llms.gemini.base import GEMINI_MODELS
from llama_index.llms.llama_cpp import LlamaCPP

from ai.src.utils.prompt_loader import SYSTEM_CONTEXT_PROMPT


def llm_chooser(model_provider: str, model_reference: str) -> LLM:
    """Choose the right LLM model based on the user input.

    Args:
        model_provider (str): Provider of the LLM model.
        model_reference (str): Reference to the LLM model, depending on the provider it can be a name, a path or a URL.
    """

    llm = None

    if model_provider == "llama_cpp":
        if model_reference.startswith("https://"):
            llm = LlamaCPP(
                model_url=model_reference,
                model_path=None,
                temperature=0.6,
                verbose=False,
                system_prompt=SYSTEM_CONTEXT_PROMPT,
            )
        elif exists(model_reference):
            llm = LlamaCPP(
                model_url=None,
                model_path=model_reference,
                temperature=0.6,
                verbose=False,
                system_prompt=SYSTEM_CONTEXT_PROMPT,
            )
        else:
            raise ValueError(f"LlamaCPP model {model_reference} not found.")
    elif model_provider == "gemini":
        if model_reference in GEMINI_MODELS:
            llm = Gemini(
                model=model_reference,
            )
        else:
            raise ValueError(
                f"Model {model_reference} not supported by Gemini. The supported models are: {", ".join([model for model in GEMINI_MODELS if model.startswith('models')])}."
            )
    else:
        raise ValueError(f"Model provider {model_provider} not supported.")

    return llm
