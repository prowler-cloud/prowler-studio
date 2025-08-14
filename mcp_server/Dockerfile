FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

RUN apk add --no-cache cargo

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

COPY --chown=prowler_studio:prowler_studio ./ /home/prowler_studio/prowler_studio

WORKDIR /home/prowler_studio/prowler_studio/mcp_server

RUN uv sync --frozen --no-dev --no-editable --no-cache

ENTRYPOINT ["uvx", "/home/prowler_studio/prowler_studio/mcp_server/"]