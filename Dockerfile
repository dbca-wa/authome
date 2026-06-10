# syntax=docker/dockerfile:1
# Prepare the base environment.
FROM dhi.io/python:3.12-debian13-dev AS build-stage
#FROM python:3.12.10-slim-bookworm AS build-stage
RUN apt-get update -y \
  && apt-get install -y passwd wget gcc libpq-dev procps\
  && rm -rf /var/lib/apt/lists/* \
  && pip install --upgrade pip

# uv install
# grab /uvx too if you need it
COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /bin/

#update permissoins
#RUN chmod 755 /etc
#RUN chmod 555 /etc/bash.bashrc

#update add user
RUN groupadd --gid 1000  app
RUN useradd --uid 1000 --gid 1000 --no-create-home --home-dir /app --shell /sbin/nologin  app


WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
COPY uv.lock pyproject.toml ./
RUN uv sync --no-group dev --link-mode=copy --compile-bytecode --no-python-downloads --frozen --no-install-project
RUN rm -f uv.lock
RUN rm -rf pyproject.toml

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

COPY fonts ./fonts

WORKDIR /app/release
COPY manage.py gunicorn_sync.py gunicorn_eventlet.py gunicorn_gevent.py testperformance testrequestheaders testrediscluster testperformance pyproject.toml captchautil.py ./
COPY authome ./authome
COPY templates ./templates
RUN export IGNORE_LOADING_ERROR=True ; python manage.py collectstatic --noinput --no-post-process

RUN cp -rf /app/release /app/dev

#comment out logger.debug to improve perfornace in production environment.
RUN find ./ -type f -iname '*.py' -exec sed -i 's/logger\.debug/#logger.debug/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -E -i 's/from\s+\.\s+import\s+performance/#from . import performance/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -E -i 's/from\s+\.\.\s+import\s+performance/#from .. import performance/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -i 's/performance\.start_processingstep/#performance.start_processingstep/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -i 's/performance\.end_processingstep/#performance.end_processingstep/g' "{}" +;

RUN find ./ -type f -iname '*.py' -exec sed -E -i 's/from\s+\.models\s+import\s+DebugLog/#from .models import DebugLog/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -E -i 's/from\s+\.\.models\s+import\s+DebugLog/#from ..models import DebugLog/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -i 's/DebugLog\.log/#DebugLog.log/g' "{}" +;
RUN find ./ -type f -iname '*.py' -exec sed -i 's/DebugLog\.attach_request/#DebugLog.attach_request/g' "{}" +;

WORKDIR /app
COPY bin ./
RUN chmod 555 *

RUN chown -R app:app /app

##################################################################################
FROM dhi.io/python:3.12-debian13-dev AS runtime-stage
#FROM python:3.12.10-slim-bookworm AS runtime-stage
LABEL org.opencontainers.image.authors=asi@dbca.wa.gov.au
LABEL org.opencontainers.image.source=https://github.com/dbca-wa/authome

RUN apt-get update -y \
  && apt-get install -y wget libpq-dev procps\
  && rm -rf /var/lib/apt/lists/* 

# Copy the user & usergroup
COPY --from=build-stage /etc/group /etc/
COPY --from=build-stage /etc/passwd /etc/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Copy over the built project and virtualenv
COPY --from=build-stage --chown=app:app /app /app

WORKDIR /app
USER app
# Run the application as the non-root user.
EXPOSE 8080
CMD ["./start_app"]
