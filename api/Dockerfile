FROM python:3.12.8-alpine3.20

# First install system build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    g++ \
    make \
    rust \
    cargo \
    git

# Install llama-deploy if it's from pip
RUN pip install llama-deploy

# First do all operations that require root
RUN addgroup -g 1000 prowler_studio && \
    adduser -u 1000 -G prowler_studio -D prowler_studio

# Install system dependencies and NLTK
RUN pip install --no-cache-dir nltk && \
    python -m nltk.downloader -d /usr/local/share/nltk_data stopwords && \
    mkdir -p /usr/local/share/nltk_data && \
    chmod -R 777 /usr/local/share/nltk_data

# Create and set permissions for venv
RUN mkdir -p /opt/venv && \
    chown -R prowler_studio:prowler_studio /opt/venv

# Install pip and poetry
RUN pip install --no-cache-dir --upgrade --ignore-installed pip && \
    pip install --no-cache-dir poetry

# Now switch to prowler_studio user
USER prowler_studio

WORKDIR /home/prowler_studio

ENV PATH="/opt/venv/bin:$PATH"
ENV PATH="/home/prowler_studio/.local/bin:$PATH"

COPY --chown=prowler_studio:prowler_studio ./poetry.lock .
COPY --chown=prowler_studio:prowler_studio ./pyproject.toml .
COPY --chown=prowler_studio:prowler_studio ./api/ ./api/
COPY --chown=prowler_studio:prowler_studio ./core/ ./core/

# Make sure the prowler_studio user has proper permissions
RUN chown -R prowler_studio:prowler_studio /opt/venv

# Install dependencies as prowler_studio user
RUN poetry config virtualenvs.in-project false && \
    poetry config virtualenvs.path /opt/venv && \
    poetry install --no-root && \
    rm -rf /home/prowler_studio/.cache/pip

# FIX bug in llamaindex framework to allow collect events in API deployment
RUN LLAMA_INDEX_PATH=$(poetry run python -c "import llama_index.core.workflow.context as m; print(m.__file__)") && \
    sed -i '0,/k: \[serializer.serialize(ev) for ev in v\]/s//str(k): \[serializer.serialize(ev) for ev in v\]/' "$LLAMA_INDEX_PATH"

RUN chmod +x ./api/container-entrypoint.sh

ENTRYPOINT [ "./api/container-entrypoint.sh" ]