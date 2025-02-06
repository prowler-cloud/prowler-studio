FROM python:3.13-alpine3.20

LABEL maintainer="https://github.com/prowler-cloud/"

RUN apk add --no-cache gcc=13.2.1_git20240309-r0 python3-dev=3.12.8-r1 musl-dev=1.2.5-r0 linux-headers=6.6-r0 ncurses=6.4_p20240420-r2

RUN addgroup -g 1000 prowler_studio && \
    adduser -u 1000 -G prowler_studio -D prowler_studio

USER prowler_studio

WORKDIR /home/prowler_studio

COPY ./pyproject.toml .
COPY ./core/ ./core/
COPY ./cli/ ./cli/
COPY ./prowler-studio ./prowler-studio

RUN pip install --no-cache-dir --upgrade --ignore-installed pip && \
    pip install --no-cache-dir poetry

ENV PATH="/home/prowler_studio/.local/bin/:$PATH"

RUN poetry config virtualenvs.in-project true && \
    poetry install --no-root && \
    rm -rf /home/prowler_studio/.cache/pip

ENTRYPOINT ["poetry", "run", "./prowler-studio"]
