
# Prowler Studio

## Installation

### From Source (CLI only)

**Requirements:**
- `git`
- `poetry`
- At least Python 3.12

```bash
git clone git@github.com:prowler-cloud/studio.git
cd studio
poetry install --with cli # Install the CLI dependencies to use from the terminal in a easy way
```

### From Source (GUI)

#### API

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

## Usage

### CLI

For now only as model is only supported Gemini Flash 1.5 model and text-embedding-004.
So for the usage you will need an API key for Gemini. Gemini has a
[free API key pricing](https://ai.google.dev/pricing#1_5flash) that can be
used to test the model. In order to get one go to [Gemini's documentation](https://ai.google.dev/gemini-api/docs/api-key)
and follow the instructions to get one. Once you have the API key, you have to set it as an environment variable:

```bash
export LLM_API_KEY="XXXXXXXX"
```

Then you can run the program with:

```bash
poetry run ./studio_cli --help
```

### Ask to create a new check

```bash
poetry run ./studio_cli ask "<prompt>"
```

To run in the interactive mode:

```bash
poetry run ./studio_cli ask
```

### API

The API is a REST API that can be used for multiple purposes. To ask a question to the AI model you can use the following command:

```bash
curl --request POST \
  --url http://localhost:4501/deployments/ChecKreationWorkflow/tasks/run \
  --header 'content-type: application/json' \
  --data '{"input": "{\"user_query\": \"<prompt>\", \"model_provider\": \"gemini\", \"model_reference\": \"1.5 Flash\"}"}'
```
