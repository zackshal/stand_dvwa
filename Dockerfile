FROM python:3.12-slim

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY flask_no_sql_indexing/ ./flask_no_sql_indexing

WORKDIR /app/flask_no_sql_indexing

CMD ["python", "app.py"]

