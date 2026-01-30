from datetime import datetime
from probe_mcp.ollamaproxy.utils.RedisDB import RedisDB
from utils.Util import Util
from uuid import uuid4
import asyncio
import argparse
import os
from passlib.hash import bcrypt
import logging
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ip_ban_db = RedisDB(hostname=os.environ.get('IP_BAN_DB'), 
                    port=os.environ.get('IP_BAN_DB_PORT'))
util_obj = Util()

async def edit_db(action: str, ip_address: str):
    await ip_ban_db.connect_db()
    match action:
        case 'block':
            now = datetime.now(tz=timezone.utc)
            ban_data = {'ip': ip_address,
                        'banned_at': now.isoformat()}
            if await ip_ban_db.upload_db_data(id=f"blocked_ip:{ip_address}", data=ban_data) > 0:
                logger.info(f"{ip_address} is banned.")

        case 'unblock':
            if await ip_ban_db.del_obj(id=f"blocked_ip:{ip_address}") > 0:
                logger.info(f"{ip_address} is unbanned.")

        case _:
            logger.error("Invalid action. Use 'block' or 'unblock'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modify the IP ban database.")
    parser.add_argument(
        '-a', '--action', 
        type=str, 
        help="Action to perform on the IP ban database (block or unblock)"
    )
    parser.add_argument(
        '-i', '--ip', 
        type=str, 
        help="IP address to act upon"
    )
    args = parser.parse_args()

    asyncio.run(edit_db(args.action, args.ip))