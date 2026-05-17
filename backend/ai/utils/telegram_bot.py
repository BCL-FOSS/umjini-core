import json
import os
from websockets.sync.client import connect
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from init_app import cl_data_db, util_obj

ws_url = f"wss://{os.getenv('SERVER_NAME')}/v1/api/core/bot/ws"
token = os.getenv("TELEGRAM_BOT_TOKEN")

async def send_to_quart(prompt: str, id: int, act: str) -> str:
    async with connect(ws_url) as ws:
        payload = json.dumps({"act": act, "prompt": prompt, "telegram_id": str(id)})
        await ws.send(payload)
        raw = await ws.recv()
        data = json.loads(raw)
        if data.get('telegram_id') and data.get('telegram_id') == str(id):
            return data.get("response")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await util_obj.check_id(connecting_id)
    if not is_authorized:
        return
    
    probe_data = await cl_data_db.get_all_data(match=f"prb:*")
    probe_info = ""
    for prb in probe_data:
        probe_info += f"Probe ID: {prb.get('id')}, Name: {prb.get('name')}, Site: {prb.get('site')}\n"

    await context.bot.send_message(chat_id=update.effective_chat.id, text="👋 Hello! I'm your umjini network admin bot.\n" \
    "I have access to the following probes:\n" + probe_info + "\n\nAvailable Commands:\n/query - send a query to the umjini\n/exec - execute net admin tasks at specified sites (probes) with umjini. Specify the probe by ID by putting 'prb_id:<ID>' at the end of your request\n"
    "/start - show this message again")

async def exec(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await util_obj.check_id(connecting_id)
    if not is_authorized:
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /exec <your command> prb_id:<probe_id>")
        return
    
    prompt = " ".join(context.args)

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
    response = await send_to_quart(prompt, connecting_id, act="exec")
    await update.message.reply_text(response)

async def query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await util_obj.check_id(connecting_id)
    if not is_authorized:
        return
    if not context.args:
        await update.message.reply_text("Usage: /query <your question>")
        return
    prompt = " ".join(context.args)
    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
    response = await send_to_quart(prompt, connecting_id, act="query")
    await update.message.reply_text(response)

async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await util_obj.check_id(connecting_id)
    if not is_authorized:
        return
    await context.bot.send_message(chat_id=update.effective_chat.id, text="Sorry, I didn't understand that command.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await util_obj.check_id(connecting_id)
    if not is_authorized:
        return
    user_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    prompt = update.message.text

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
        
    response = await send_to_quart(prompt, user_id, act="message")
    await update.message.reply_text(response)

def main() -> None:
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set in environment.")

    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("query", query))
    app.add_handler(CommandHandler("exec", exec))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.COMMAND, unknown))  
    app.run_polling()

if __name__ == "__main__":
    main()