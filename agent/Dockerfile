FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# build-essential במקרה שאין wheel מוכן ל-psutil (לרוב יש)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY agent_updated.py ./agent_updated.py
COPY run_agent.sh ./run_agent.sh
RUN chmod +x ./run_agent.sh

CMD ["/bin/sh", "./run_agent.sh"]
