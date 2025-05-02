FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

COPY --chown=prowler_studio:prowler_studio ./api /home/prowler_studio/prowler_studio/api
COPY --chown=prowler_studio:prowler_studio ./core /home/prowler_studio/prowler_studio/core
COPY --chown=prowler_studio:prowler_studio ./uv.lock /home/prowler_studio/prowler_studio/uv.lock
COPY --chown=prowler_studio:prowler_studio ./pyproject.toml /home/prowler_studio/prowler_studio/pyproject.toml

WORKDIR /home/prowler_studio/prowler_studio/api

RUN uv sync --frozen --no-dev --no-editable && rm -rf /home/prowler_studio/prowler_studio/core

ENTRYPOINT ["/home/prowler_studio/prowler_studio/.venv/bin/prowler-studio-api"]
