#!/bin/sh

nohup chroma run --path /home/quart/utils/chromadb_data --port 6000 > /var/log/chroma.log 2>&1 &

nohup /opt/telegram-bot-api/bin/telegram-bot-api --api-id "$TELEGRAM_API_ID" --api-hash "$TELEGRAM_API_HASH" --local > /var/log/telegram_bot_api.log 2>&1 &

nohup python3 -m utils.telegram_bot > /var/log/telegram_bot.log 2>&1 &

uvicorn app:app --host 0.0.0.0 --port 8000