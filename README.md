
# Prowler Studio

## Installation

### From Source

**Requirements:**
- `git`
- `poetry`
- At least Python 3.12

```bash
git clone git@github.com:prowler-cloud/studio.git
cd studio
poetry install
```

## Usage

For the usage is necessary to have an API key to use the Gemini models.

For now only as models is only supported Gemini Flash 1.5 model and text-embedding-004.
Gemini has a [free API key pricing](https://ai.google.dev/pricing#1_5flash) that can be
used to test the model. In order to get one go to [Gemini's documentation](https://ai.google.dev/gemini-api/docs/api-key)
and follow the instructions to get one. Once you have the API key, you have to set it as an environment variable:

```bash
export GOOGLE_API_KEY="XXXXXXXX"
```

Then you can run the program with:

```bash
poetry run python __main__.py "<prompt>"
```
