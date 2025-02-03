from simple_term_menu import TerminalMenu

from core.src.utils.model_chooser import SUPPORTED_EMBEDDING_MODELS, SUPPORTED_LLMS


def get_llm_provider() -> str:
    provider_menu = TerminalMenu(
        title="Select the model provider",
        menu_entries=list(SUPPORTED_LLMS.keys()),
    )
    provider_index = provider_menu.show()
    return list(SUPPORTED_LLMS.keys())[provider_index]


def get_llm_reference(provider: str) -> str:
    if provider in SUPPORTED_LLMS:
        model_menu = TerminalMenu(
            title="Select the model reference",
            menu_entries=SUPPORTED_LLMS[provider],
        )
    else:
        raise ValueError(f"Model provider {provider} have not supported models yet")
    model_index = model_menu.show()
    return SUPPORTED_LLMS[provider][model_index]


def get_embedding_model_provider() -> str:
    provider_menu = TerminalMenu(
        title="Select the embedding model provider",
        menu_entries=list(SUPPORTED_EMBEDDING_MODELS.keys()),
    )
    provider_index = provider_menu.show()
    return list(SUPPORTED_EMBEDDING_MODELS.keys())[provider_index]


def get_embedding_model_reference(provider: str) -> str:
    if provider in SUPPORTED_EMBEDDING_MODELS:
        model_menu = TerminalMenu(
            title="Select the embedding model reference",
            menu_entries=SUPPORTED_EMBEDDING_MODELS[provider],
        )
    else:
        raise ValueError(f"Model provider {provider} have not supported models yet")
    model_index = model_menu.show()
    return SUPPORTED_EMBEDDING_MODELS[provider][model_index]
