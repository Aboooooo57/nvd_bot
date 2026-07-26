FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nvd_bot/ ./nvd_bot/
COPY nvd_bot.py .

RUN mkdir -p data/repos

# Kept last: ENV invalidates every layer below it, and these change on every
# build. .git is excluded from the build context, so the sha has to be passed
# in rather than derived here.
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ENV GIT_SHA=$GIT_SHA \
    BUILD_DATE=$BUILD_DATE

CMD ["python", "-u", "nvd_bot.py"]
