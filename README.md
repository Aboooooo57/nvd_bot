Here is a professional and complete `README.md` for your project. You can save this file in your project folder.

***

# 🛡️ NVD Vulnerability Telegram Bot

A Python-based Telegram bot that monitors the **National Vulnerability Database (NVD)** API for new security vulnerabilities (CVEs). It runs hourly, filters for specific technologies (like Python, React, Next.js), and sends real-time alerts to a Telegram chat.

## ✨ Features

*   **Hourly Updates**: Checks for new CVEs published within the last hour.
*   **Tech Stack Filtering**: Only sends alerts for technologies you care about (e.g., FastAPI, Next.js, React, TypeScript, Python).
*   **Smart De-duplication**: Uses a local JSON database to ensure you never receive the same alert twice.
*   **Status Tracking**: Handles "Pending" analysis states and displays severity scores when available.
*   **Dockerized**: Ready to deploy with Docker Compose.
*   **HTML Safety**: Sanitized inputs to prevent Telegram API formatting errors.

## 📂 Project Structure

```text
nvd_bot/
├── data/              # Stores the database of seen CVEs (mapped via volume)
├── nvd_bot.py         # Main bot logic
├── requirements.txt   # Python dependencies
├── Dockerfile         # Docker image definition
├── docker-compose.yml # Container orchestration
└── README.md          # Documentation
```

## 🚀 Getting Started

### Prerequisites

*   **Docker** and **Docker Compose** installed.
*   A **Telegram Bot Token** (from [@BotFather](https://t.me/BotFather)).
*   A **Telegram Chat ID** (from [@userinfobot](https://t.me/userinfobot)).
*   *(Optional)* **NVD API Key** (Get one [here](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits).

### 1. Installation

Create a folder for your project and add the necessary files (`nvd_bot.py`, `Dockerfile`, `docker-compose.yml`, `requirements.txt`) as defined in your development process.

### 2. Configuration

Open `docker-compose.yml` and add your credentials:

```yaml
services:
  nvd-bot:
    environment:
      - TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
      - CHAT_ID=123456789
      - NVD_API_KEY=your-nvd-api-key-here  # Optional
```

### 3. Customizing the Watchlist

To change the technologies you want to monitor, open `nvd_bot.py` and look for the `WATCHLIST` variable:

```python
# 🚨 EDIT THIS LIST: Case-insensitive keywords to watch for
WATCHLIST = [
    "fastapi",
    "next.js", "nextjs",
    "react", "reactjs",
    "python",
    "typescript",
    "node.js",
    "django", "flask"
]
```

### 4. Running the Bot

Run the bot in the background using Docker Compose:

```bash
docker compose up -d
```

Check the logs to ensure it is running correctly:

```bash
docker compose logs -f
```

## 🛠️ Development (Local Run)

If you want to run it without Docker for testing:

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Set Environment Variables** (Linux/Mac):
    ```bash
    export TELEGRAM_BOT_TOKEN="your_token"
    export CHAT_ID="your_chat_id"
    ```
3.  **Run the Script**:
    ```bash
    python nvd_bot.py
    ```

## ⚠️ Notes

*   **Severity "PENDING"**: When a CVE is first published, NVD often marks it as "Received" or "Awaiting Analysis." The bot will show these as **PENDING** with an hourglass icon ⏳.
*   **Persistence**: The `data/` folder is mounted as a volume. This ensures that the list of already sent CVEs (`seen_cves.json`) is not lost if you restart the container.

## 🤝 Contributing

Feel free to fork this project and add more filters or integrations (like Slack or Discord)!

## 📄 License

This project is open-source.