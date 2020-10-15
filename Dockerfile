# Prepare the base environment.
FROM python:3.7.8-slim-buster as builder_base_authome
MAINTAINER asi@dbca.wa.gov.au
RUN apt-get update -y \
  && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y wget python3-dev \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --upgrade pip

# Install Python libs from pyproject.toml.
FROM builder_base_authome as python_libs_authome
WORKDIR /app
ENV POETRY_VERSION=1.0.5
RUN pip install "poetry==$POETRY_VERSION"
RUN python -m venv /venv
COPY poetry.lock pyproject.toml /app/
RUN poetry config virtualenvs.create false \
  && poetry install --no-dev --no-interaction --no-ansi

# Install the project.
FROM python_libs_authome
COPY manage.py gunicorn.py ./
COPY authome ./authome
# Run the application as the www-data user.
USER www-data
EXPOSE 8080
CMD ["gunicorn", "authome.wsgi", "--config", "gunicorn.py"]
