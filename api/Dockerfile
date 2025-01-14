FROM llamaindex/llama-deploy:main

LABEL maintainer="https://github.com/prowler-cloud"

RUN addgroup --gid 1000 prowler && \
    adduser -u 1000 --gid 1000 --disabled-login prowler

USER prowler

WORKDIR /home/prowler

COPY --chown=prowler:prowler ./pyproject.toml .

COPY --chown=prowler:prowler ./api/ ./api/

COPY --chown=prowler:prowler ./core/ ./core/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

ENV PATH="/home/prowler/.local/bin:$PATH"

RUN poetry config virtualenvs.in-project true && \
    poetry install --no-root --with api && \
    rm -rf /home/prowler/.cache/pip

# FIX bug in llamaindex framework to allow collect events in API deployment
RUN sed -i '0,/k: \[serializer.serialize(ev) for ev in v\]/s//str(k): \[serializer.serialize(ev) for ev in v\]/' /home/prowler/.venv/lib/python3.12/site-packages/llama_index/core/workflow/context.py

ENTRYPOINT [ "./api/container-entrypoint.sh" ]
