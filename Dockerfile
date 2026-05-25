FROM python:3.12-slim

# Imposta la directory di lavoro nel container
WORKDIR /app

# Copia il file dei requisiti e installa le dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia tutto il resto (incluso scanner_bunny.py, pack.json e la cartella site)
COPY . .

# Crea le cartelle necessarie prima dell'esecuzione (opzionale ma sicuro)
RUN mkdir -p DIABLO-LOGV9/DIABLO_FILES_SPLIT
RUN mkdir -p site

# Comando per avviare lo script
CMD ["python", "scanner_bunny.py"]
