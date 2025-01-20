import asyncio
import os
import sys
from typing import Literal

import typer
from loguru import logger
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Prompt
from simple_term_menu import TerminalMenu
from typing_extensions import Annotated

from core.src.utils.build_rag_dataset import build_vector_store
from core.src.utils.model_chooser import SUPPORTED_EMBEDDING_MODELS, SUPPORTED_LLMS
from core.src.workflow import ChecKreationWorkflow


async def run_check_creation_workflow(
    user_query: str, model_provider: str, model_reference: str, api_key: str
) -> dict | str:
    workflow = ChecKreationWorkflow(timeout=60, verbose=False)
    result = await workflow.run(
        user_query=user_query,
        model_provider=model_provider,
        model_reference=model_reference,
        api_key=api_key,
        verbose=False,
    )
    return result


app = typer.Typer()

console = Console()


def set_app_log_level(
    log_level: Literal[
        "TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"
    ],
) -> None:
    """Set the minimum log level for the application.

    This function updates the logger to direct log output to a custom log capturing object,
    filtering logs based on the provided `log_level`. Logs below the specified level will not be shown.

    Args:
        log_level (Literal["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]):
            The minimum level of logs to display. The available levels are:
            - "TRACE"
            - "DEBUG"
            - "INFO"
            - "SUCCESS"
            - "WARNING"
            - "ERROR"
            - "CRITICAL"
        log_capture (LogCapture):
            An instance of the custom log capture object
    Raises:
        ValueError: If the provided log level is invalid.
    """

    valid_log_levels = {
        "TRACE",
        "DEBUG",
        "INFO",
        "SUCCESS",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }
    if log_level not in valid_log_levels:
        raise ValueError(
            f"Invalid log level: {log_level}. Valid options are: {', '.join(valid_log_levels)}"
        )

    # Remove existing log handlers and set the new log level
    logger.remove()
    logger.add(
        sys.stderr, level=log_level
    )  # TODO: Use a custom log handler object passed as an argument, https://loguru.readthedocs.io/en/stable/resources/recipes.html#capturing-standard-stdout-stderr-and-warnings. Probably cosole prints should be set in this custom handler class, it should be used as view in MVC pattern


def get_llm_provider() -> str:
    provider_menu = TerminalMenu(
        title="Select the model provider",
        menu_entries=list(SUPPORTED_LLMS.keys()),
    )
    provider_index = provider_menu.show()
    return list(SUPPORTED_LLMS.keys())[provider_index]


def get_llm_reference(provider: str) -> str:
    if provider == "gemini":
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
    if provider == "gemini":
        model_menu = TerminalMenu(
            title="Select the embedding model reference",
            menu_entries=SUPPORTED_EMBEDDING_MODELS[provider],
        )
    else:
        raise ValueError(f"Model provider {provider} have not supported models yet")
    model_index = model_menu.show()
    return SUPPORTED_EMBEDDING_MODELS[provider][model_index]


def get_user_prompt() -> str:
    return Prompt.ask("\n[bold]Message Prowler Studio :robot:[/bold]\n╰┈➤")


@app.command()
def ask(
    user_query: Annotated[str, typer.Argument(help="User query")] = "",
    model_provider: Annotated[
        str,
        typer.Option(help="The model provider to use"),
    ] = "",
    model_reference: Annotated[
        str, typer.Option(help="The specific model reference to use")
    ] = "",
    llm_api_key: Annotated[
        str, typer.Option(envvar="LLM_API_KEY", help="LLM API key")
    ] = "",  # Is optional because in a future it can support local models that does not need an API key
    embedding_model_api_key: Annotated[
        str,
        typer.Option(envvar="EMBEDDING_MODEL_API_KEY", help="Embedding model API key"),
    ] = "",  # TODO: review this because in a future it should support different keys for embedding models and LLM models
    rag_path: Annotated[
        str, typer.Option(help="Path to the indexed data storage", exists=True)
    ] = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "../../", "core", "indexed_data_db"
    ),
    log_level: Annotated[str, typer.Option(help="Set the log level")] = "INFO",
):
    """Ask a question to Prowler Studio

    Args:
        user_query: User query
        model_provider: The model provider to use
        model_reference: The specific model reference to use
        llm_api_key: LLM API key
        embedding_model_api_key: Embedding model API key
        rag_path: Path to the indexed data storage
        log_level: Set the log level
    """
    try:
        if not model_provider:
            model_provider = get_llm_provider()
        if not model_reference:
            model_reference = get_llm_reference(model_provider)
        if not user_query:
            user_query = get_user_prompt()

        if user_query:
            if os.path.exists(rag_path):
                set_app_log_level(log_level)

                result = asyncio.run(
                    run_check_creation_workflow(
                        user_query=user_query,
                        model_provider=model_provider,
                        model_reference=model_reference,
                        api_key=llm_api_key,
                    )
                )

                console.print(
                    "[bold green]Prowler Studio :robot: says:\n[/bold green]",
                    Markdown(result),
                )

            else:
                raise FileNotFoundError(
                    "RAG dataset not found, you can build it using `build_check_rag` command"
                )
        else:
            raise ValueError("User query can't be empty")
    except Exception as e:
        console.print(f"[bold red]ERROR :cross_mark:: {e}[/bold red]")
        typer.Exit(code=1)


@app.command()
def build_check_rag(
    github_token: Annotated[
        str,
        typer.Option(
            envvar="GITHUB_TOKEN",
            help="GitHub token to extract data from Prowler repository. Needed to make more requests to the GitHub API",
        ),
    ],
    rag_path: Annotated[
        str, typer.Argument(help="Path to the indexed data storage")
    ] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "core",
        "indexed_data_db",
    ),
    model_provider: Annotated[str, typer.Option(help="The model provider to use")] = "",
    model_reference: Annotated[
        str, typer.Option(help="The specific model to use")
    ] = "",
    embedding_model_api_key: Annotated[
        str,
        typer.Option(envvar="EMBEDDING_MODEL_API_KEY", help="Embedding model API key"),
    ] = "",
):
    """Build RAG dataset

    Args:
        github_token: GitHub token to extract data from Prowler repository
        rag_path: Path to the indexed data storage
        model_provider: The model provider to use
        model_reference: The specific model reference to use
        embedding_model_api_key: Embedding model API key
    """
    try:
        if os.path.exists(rag_path):
            raise FileExistsError(f"RAG dataset already exists in the path: {rag_path}")
        else:
            if not model_provider:
                model_provider = get_embedding_model_provider()
            if not model_reference:
                model_reference = get_embedding_model_reference(model_provider)
            build_vector_store(
                github_token=github_token,
                model_provider=model_provider,
                model_reference=model_reference,
                api_key=embedding_model_api_key,
                vector_store_path=rag_path,
            )
        console.print("[bold green]RAG dataset built successfully![/bold green]")
    except Exception as e:
        console.print(f"[bold red]ERROR: {e}[/bold red]")
        typer.Exit(code=1)
