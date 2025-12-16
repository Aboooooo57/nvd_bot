# Use a lightweight Python image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the bot code
COPY nvd_bot.py .

# Create the data directory
RUN mkdir -p data

# Run the bot with unbuffered output (so logs show up immediately)
CMD ["python", "-u", "nvd_bot.py"]