FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

# Install required system dependencies for terminal menus
RUN apk add --no-cache ncurses=6.5_p20241006-r3

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

COPY --chown=prowler_studio:prowler_studio ./cli /home/prowler_studio/prowler_studio/cli
COPY --chown=prowler_studio:prowler_studio ./core /home/prowler_studio/prowler_studio/core
COPY --chown=prowler_studio:prowler_studio ./uv.lock /home/prowler_studio/prowler_studio/uv.lock
COPY --chown=prowler_studio:prowler_studio ./pyproject.toml /home/prowler_studio/prowler_studio/pyproject.toml

WORKDIR /home/prowler_studio/prowler_studio/cli

RUN uv sync --frozen --no-dev --no-editable

ENTRYPOINT ["/home/prowler_studio/prowler_studio/.venv/bin/prowler-studio"]
