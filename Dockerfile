FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p risultati/DIABLO_FILES_SPLIT
RUN mkdir -p site

CMD ["python", "scanner_bunny.py"]
