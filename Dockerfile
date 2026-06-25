FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nvd_bot/ ./nvd_bot/
COPY nvd_bot.py .

RUN mkdir -p data/repos

CMD ["python", "-u", "nvd_bot.py"]
