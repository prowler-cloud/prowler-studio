FROM python:3.12.8-alpine3.20

LABEL maintainer="https://github.com/prowler-cloud/"

RUN apk add --no-cache gcc g++ python3-dev musl-dev linux-headers ncurses rust cargo

RUN addgroup -g 1000 prowler_studio && \
    adduser -u 1000 -G prowler_studio -D prowler_studio

USER prowler_studio

WORKDIR /home/prowler_studio

COPY ./pyproject.toml .
COPY ./core/ ./core/
COPY ./cli/ ./cli/
COPY ./prowler-studio ./prowler-studio

RUN pip install --no-cache-dir --upgrade --ignore-installed pip && \
    pip install --no-cache-dir poetry prowler

ENV PATH="/home/prowler_studio/.local/bin/:$PATH"

RUN poetry config virtualenvs.in-project true
RUN poetry install --no-root -vvv
RUN rm -rf /home/prowler_studio/.cache/pip


ENTRYPOINT ["poetry", "run", "./prowler-studio"]
