FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

RUN apk add --no-cache cargo=1.83.0-r0

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

COPY --chown=prowler_studio:prowler_studio ./core /home/prowler_studio/prowler_studio/core
COPY --chown=prowler_studio:prowler_studio ./mcp_server /home/prowler_studio/prowler_studio/mcp_server
COPY --chown=prowler_studio:prowler_studio ./pyproject.toml /home/prowler_studio/prowler_studio/pyproject.toml
COPY --chown=prowler_studio:prowler_studio ./uv.lock /home/prowler_studio/prowler_studio/uv.lock

WORKDIR /home/prowler_studio/prowler_studio/mcp_server

RUN uv sync --frozen --no-dev --no-editable --no-cache && rm -rf /home/prowler_studio/prowler_studio/core/

ENTRYPOINT ["uvx", "/home/prowler_studio/prowler_studio/mcp_server/"]
