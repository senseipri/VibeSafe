FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-interaction --no-root

COPY . .

CMD ["sh", "-c", "uvicorn vibesafe.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]