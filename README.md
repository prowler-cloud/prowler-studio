
# Prowler Studio

Prowler Studio is an AI assistant that helps you to create checks for Prowler. It can be used as a CLI tool or as a web application.

## LLM Configuration

For now only as model is only supported Gemini Flash 1.5 model and text-embedding-004 from Google.
So for the usage you will need an API key for Gemini. Gemini has a
[free API key pricing](https://ai.google.dev/pricing#1_5flash) that can be
used to test the model. In order to get one go to [Gemini's documentation](https://ai.google.dev/gemini-api/docs/api-key)
and follow the instructions to get one. Once you have the API key, you have to set it as an environment variable:

```bash
export GOOGLE_API_KEY="XXXXXXXX"
export EMBEDDING_MODEL_API_KEY="XXXXXXXX"
```

## Studio App

The Studio App is a web application that allows you to ask questions to the AI model and get the answer in a more user-friendly way.

### Features

- Get the answer in a more user-friendly way
- API powered by LlamaDeploy

### Installation

#### Docker

**Requirements:**
- `git`
- `docker`

First of all is download the repository:

```bash
git clone git@github.com:prowler-cloud/studio.git
```

Then you can build the Docker image:

```bash
docker build -f ./api/Dockerfile -t prowler-studio-api:latest . # Build the API image
cd ./ui
docker build -f ./Dockerfile -t prowler-studio-ui:latest .  # Build the UI image
```

Now you can run the Docker containers using `docker-compose` from the root of the repository:

> [!IMPORTANT]
> In order to work some environment variables are needed. Use the `.env.template` file as a template to create a `.env` file with the needed variables.
> For now is only supported Gemini and Google embedding model, so the `GOOGLE_API_KEY` and `EMBEDDING_MODEL_API_KEY` must be the same.
> To get one go to [Gemini's documentation](https://ai.google.dev/gemini-api/docs/api-key) and follow the instructions to get one.

```bash
docker compose up -d
```

Now you can access the UI from your browser at `http://localhost:80`.

#### Local

##### API

**Requirements:**
- `git`
- `poetry`
- At least Python 3.12

```bash
git clone git@github.com:prowler-cloud/studio.git
cd studio
poetry install --with api
```

To start the API server run:

```bash
poetry run python -m llama_deploy.apiserver
```

Now from other terminal deploy the Workflow to get the answer from the AI model:

```bash
poetry run llamactl deploy api/deployment.yml
```

##### UI

**Requirements:**
- `npm`

```bash
cd ui
npm install
```

To start the UI server run:

```bash
npm run start
```

Now you can access the UI from your browser at `http://localhost:3000`.

### Usage

Just type your check creation request in the input field and press "Enter"!


![Prowler Studio Check Creation](docs/img/prowler_studio_web_interface.png)

## CLI

The CLI is a command-line tool that allows you to ask questions to the AI model and get the answer in a more programmatic way.

### Features

- Ask questions to the AI system
- RAG dataset creation
- Configurable
- Save checks in your Prowler local repository!

### Installation

#### Local

**Requirements:**
- `git`
- `poetry`
- At least Python 3.12

```bash
git clone git@github.com:prowler-cloud/studio.git
cd studio
poetry install --with cli # Install the CLI dependencies to use from the terminal in a easy way
```

### Usage

To use the CLI you can consult the help message:

```bash
poetry run ./prowler-studio --help
```

#### Aviable commands

- `create-check`: Create a check.
- `build-check-rag`: Build a RAG dataset updated with master (the RAG dataset is already in the repository, this command is to update it with new possible checks).

##### Check creation examples

To create a check you can use the `create-check` command:

```bash
# AWS
poetry run ./prowler-studio create-check "Checks for Amazon EC2 security groups with inbound rules allowing unrestricted ICMP access."
# Azure
poetry run ./prowler-studio create-check "Ensure that Azure App has a backup retention policy configured."
# GCP
poetry run ./prowler-studio create-check "Ensure that Compute Engine restarts instances automatically when terminated due to non-user reasons."
```

You can also run in the interactive mode just running the command without arguments:

```bash
poetry run ./prowler-studio create-check
```

#### Configuration

The CLI can be configured using the `cli/config/config.yml` file. The file is already created in the repository and you can change the values to fit your needs.
The supported values for the configuration are:

- `llm_provider`: The LLM provider to use. The supported values are:
  - `gemini`
- `llm_reference`: How the model is named in the provided provider. The supported values depend on the provider:
  - For `gemini` provider:
    - `1.5 Flash`: The Gemini Flash 1.5 model.
- `embedding_model_provider`: The embedding model provider to use, it only affects on the `build-check-rag` command. The supported values are:
  - `gemini`
- `embedding_model_reference`: How the model is named in the provided provider, it only affects on the `build-check-rag` command. The supported values depend on the provider:
  - For `gemini` provider:
    - `text-embedding-004`: The Google text-embedding-004 model.
- `prowler_repo_path`: The path to the Prowler repository in your local machine. It is used to save the checks in the repository.
