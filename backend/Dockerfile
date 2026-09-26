FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy app codebase
COPY . .

# Pre-train / load demo models
RUN python -c "from models.phishing_classifier import PhishingClassifier; PhishingClassifier().train_demo_model()" || true
RUN python -c "from models.neural_net import PhishNetManager; PhishNetManager().train_demo_network(epochs=15)" || true

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
