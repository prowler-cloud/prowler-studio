from os.path import exists

from llama_index.core.llms.llm import LLM
from llama_index.llms.llama_cpp import LlamaCPP


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
            )
        elif exists(model_reference):
            llm = LlamaCPP(
                model_url=None,
                model_path=model_reference,
                temperature=0.6,
                verbose=False,
            )
        else:
            raise ValueError(f"LlamaCPP model {model_reference} not found")
    else:
        raise ValueError(f"Model provider {model_provider} not supported")

    return llm
