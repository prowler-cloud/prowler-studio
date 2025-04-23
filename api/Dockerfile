FROM python:3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

# Install system dependencies
RUN apk add --no-cache \
    gcc=14.2.0-r4 \
    g++=14.2.0-r4 \
    linux-headers=6.6-r1 \
    make=4.4.1-r2 \
    gfortran=14.2.0-r4 \
    openblas-dev=0.3.28-r0

RUN addgroup -g 1000 prowler_studio && \
    adduser -D -u 1000 -G prowler_studio prowler_studio

USER prowler_studio

WORKDIR /home/prowler_studio

COPY --chown=prowler_studio:prowler_studio ./pyproject.toml .
COPY --chown=prowler_studio:prowler_studio ./poetry.lock* ./

COPY --chown=prowler_studio:prowler_studio ./api/ ./api/
COPY --chown=prowler_studio:prowler_studio ./core/ ./core/

RUN pip install --no-cache-dir --upgrade --ignore-installed pip && \
    pip install --no-cache-dir poetry

ENV PATH="/home/prowler_studio/.local/bin:$PATH"

RUN poetry config virtualenvs.in-project true && \
    poetry install --with api --no-root && \
    rm -rf /home/prowler_studio/.cache/pip

ENTRYPOINT ["poetry", "run", "python", "-m", "uvicorn", "api.src.main:app", "--host", "0.0.0.0", "--port", "8000"]
