FROM python:3.12-slim

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY flask_redis_indexing/ ./flask_redis_indexing

WORKDIR /app/flask_redis_indexing

CMD ["python", "app.py"]

