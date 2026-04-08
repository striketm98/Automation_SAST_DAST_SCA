FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY . /app

EXPOSE 6200

CMD ["python", "-m", "oasm_api"]
