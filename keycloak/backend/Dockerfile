# Použití menšího a bezpečnějšího image
FROM python:3.13-slim

# Nastavení pracovního adresáře
WORKDIR /backend

# Zabraňuje vytváření pyc souborů a zapíná okamžitý výstup do logů
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Instalace závislostí
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Kopírování zdrojového kódu
COPY ./src /backend/src

# Nastavení pracovního adresáře do složky se zdrojovým kódem
WORKDIR /backend/src

# Exponování portu
EXPOSE 8000

# Spuštění aplikace
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
