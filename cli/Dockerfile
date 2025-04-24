FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

COPY --chown=prowler_studio:prowler_studio ./cli /home/prowler_studio/cli
COPY --chown=prowler_studio:prowler_studio ./core /home/prowler_studio/core
COPY --chown=prowler_studio:prowler_studio ./uv.lock /home/prowler_studio/uv.lock
COPY --chown=prowler_studio:prowler_studio ./pyproject.toml /home/prowler_studio/pyproject.toml

WORKDIR /home/prowler_studio/

# With sed remoce all no need files (api, README.md, LICENSE)
RUN sed -i '/api/d' /home/prowler_studio/pyproject.toml && \
    sed -i '/\[project\.optional-dependencies\]/,+2d' /home/prowler_studio/pyproject.toml && \
    sed -i '/README.md/d' /home/prowler_studio/pyproject.toml && \
    sed -i '/LICENSE/d' /home/prowler_studio/pyproject.toml

RUN uv sync --no-dev && uv tool install -e ./cli

ENTRYPOINT ["/home/prowler_studio/.local/bin/prowler-studio"]
