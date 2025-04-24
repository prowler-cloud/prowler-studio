FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

COPY --chown=prowler_studio:prowler_studio ./api /home/prowler_studio/api
COPY --chown=prowler_studio:prowler_studio ./core /home/prowler_studio/core
COPY --chown=prowler_studio:prowler_studio ./uv.lock /home/prowler_studio/uv.lock
COPY --chown=prowler_studio:prowler_studio ./pyproject.toml /home/prowler_studio/pyproject.toml

WORKDIR /home/prowler_studio/

# With sed remoce all no need files (cli, README.md, LICENSE)
RUN sed -i '/cli/d' /home/prowler_studio/pyproject.toml && \
    sed -i '/README.md/d' /home/prowler_studio/pyproject.toml && \
    sed -i '/LICENSE/d' /home/prowler_studio/pyproject.toml

RUN uv sync --no-dev --extra api

ENTRYPOINT ["uv", "run", "--no-dev", "prowler-studio-api"]
