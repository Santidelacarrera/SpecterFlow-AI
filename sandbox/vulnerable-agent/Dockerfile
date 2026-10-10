FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 sf
COPY main.py .
USER sf
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:9000/health')"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"]
