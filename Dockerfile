# syntax=docker/dockerfile:1
# Prepare the base environment.
FROM python:3.12.10-slim-bookworm AS builder_base_authome
LABEL org.opencontainers.image.authors=asi@dbca.wa.gov.au
LABEL org.opencontainers.image.source=https://github.com/dbca-wa/authome
RUN apt-get update -y \
  && apt-get upgrade -y \
  && apt-get install -y wget libmagic-dev gcc binutils python3-dev libpq-dev procps\
  && rm -rf /var/lib/apt/lists/* \
  && pip install --upgrade pip

#install and config poetry
WORKDIR /app
ARG POETRY_VERSION=1.8.3
RUN pip install --root-user-action=ignore poetry==${POETRY_VERSION}
COPY poetry.lock pyproject.toml /app/
RUN poetry config virtualenvs.create false \
  && poetry install --only main --no-interaction --no-ansi

#update permissoins
RUN chmod 755 /etc
RUN chmod 555 /etc/bash.bashrc

#update add user
RUN addgroup -gid 1000 app
RUN adduser -uid 1000 --gid 1000 --no-create-home --disabled-login app

# Install Python libs from pyproject.toml.
FROM builder_base_authome AS python_libs_authome
WORKDIR /app
COPY fonts ./fonts

WORKDIR /app/release
# Install the project.
FROM python_libs_authome
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
RUN echo "#!/bin/bash \n\
if [[ \"\$RUNNING_MODE\" == \"gevent\" ]]; then \n\
    config=\"gunicorn_gevent.py\" \n\
elif [[ \"\$RUNNING_MODE\" == \"eventlet\" ]]; then \n\
    config=\"gunicorn_eventlet.py\" \n\
else \n\
    config=\"gunicorn_sync.py\" \n\
fi \n\
if [[ \"\$DEBUG\" == \"True\" || \"\${LOGLEVEL}\" == \"DEBUG\" ]]; then \n\
    echo \"Running in dev mode\" \n\
    cd /app/dev && gunicorn authome.wsgi --config=\${config} \n\
else \n\
    echo \"Running in release mode\" \n\
    cd /app/release && gunicorn authome.wsgi --config=\${config} \n\
fi \n\
" > start_app

RUN chmod 555 start_app

RUN echo "#!/bin/bash \n\
if [[ \"\$DEBUG\" == \"True\" || \"\${LOGLEVEL}\" == \"DEBUG\" ]]; then \n\
    echo \"Running in dev mode\" \n\
    cd /app/dev && python manage.py \"\$@\" \n\
else \n\
    echo \"Running in release mode\" \n\
    cd /app/release && python manage.py \"\$@\" \n\
fi \n\
" > run_command

RUN chmod 555 run_command

RUN chown -R app:app /app

# Run the application as the non-root user.
USER app
EXPOSE 8080
CMD ["./start_app"]
