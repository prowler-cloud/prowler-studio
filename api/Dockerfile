FROM llamaindex/llama-deploy:main

LABEL maintainer="https://github.com/prowler-cloud"

RUN addgroup --gid 1000 prowler_studio && \
    adduser -u 1000 --gid 1000 --disabled-login prowler_studio

USER prowler_studio

WORKDIR /home/prowler_studio

COPY --chown=prowler_studio:prowler_studio ./pyproject.toml .

COPY --chown=prowler_studio:prowler_studio ./api/ ./api/

COPY --chown=prowler_studio:prowler_studio ./core/ ./core/

RUN pip install --no-cache-dir --upgrade --ignore-installed pip && \
    pip install --no-cache-dir poetry

ENV PATH="/home/prowler_studio/.local/bin:$PATH"

RUN poetry config virtualenvs.in-project true && \
    poetry install --no-root --with api && \
    rm -rf /home/prowler_studio/.cache/pip

# FIX bug in llamaindex framework to allow collect events in API deployment
RUN sed -i '0,/k: \[serializer.serialize(ev) for ev in v\]/s//str(k): \[serializer.serialize(ev) for ev in v\]/' /home/prowler_studio/.venv/lib/python3.12/site-packages/llama_index/core/workflow/context.py

ENTRYPOINT [ "./api/container-entrypoint.sh" ]
