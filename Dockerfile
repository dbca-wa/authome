# Prepare the base environment.
FROM python:3.10.12-slim-buster as builder_base_authome
MAINTAINER asi@dbca.wa.gov.au
LABEL org.opencontainers.image.source https://github.com/dbca-wa/authome
RUN apt-get update -y \
  && apt-get upgrade -y \
  && apt-get install -y wget libmagic-dev gcc binutils python3-dev libpq-dev \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --upgrade pip

#install and config poetry
WORKDIR /app
ENV POETRY_VERSION=1.5.1
RUN pip install "poetry==$POETRY_VERSION"
COPY poetry.lock pyproject.toml /app/
RUN poetry config virtualenvs.create false \
  && poetry install --only main --no-interaction --no-ansi

# Install Python libs from pyproject.toml.
FROM builder_base_authome as python_libs_authome
WORKDIR /app/release
# Install the project.
FROM python_libs_authome
COPY manage.py gunicorn.py testperformance testrequestheaders testrediscluster ./
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
if [[ \"\$DEBUG\" == \"True\" || \"\${LOGLEVEL}\" == \"DEBUG\" ]]; then \n\
    echo \"Running in dev mode\" \n\
    cd /app/dev && gunicorn authome.wsgi --bind=:8080 --config=gunicorn.py \n\
else \n\
    echo \"Running in release mode\" \n\
    cd /app/release && gunicorn authome.wsgi --bind=:8080 --config=gunicorn.py \n\
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

# Run the application as the www-data user.
USER www-data
EXPOSE 8080
CMD ./start_app
