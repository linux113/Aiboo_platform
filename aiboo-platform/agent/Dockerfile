# Requires .dockerignore in same directory to exclude __pycache__, .env, etc.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8001
CMD ["python", "run_api.py"]
