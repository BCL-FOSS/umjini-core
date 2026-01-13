from probe_mcp.ollamaproxy.utils.RedisDB import RedisDB
from utils.Util import Util
from uuid import uuid4
import asyncio
import argparse
import os
from passlib.hash import bcrypt
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

cl_auth_db = RedisDB(hostname=os.environ.get('CLIENT_AUTH_DB'), 
                     port=os.environ.get('CLIENT_AUTH_DB_PORT'))
util_obj = Util()


async def generate_registration_key(user: str):
    if len(user) < 1 or len(user) < 5:
        logger.error("Username must be provided and cannot be empty.")
        return
    
    await cl_auth_db.connect_db()

    if await cl_auth_db.get_all_data(match=f'reg_key:{user}*', cnfrm=True) is True:
        logger.error(f"Registration key already exists for user '{user}'")
        return

    key = str(uuid4())
    key_hash = bcrypt.hash(key)
    reg_key_id = f"reg_key:{user}:{util_obj.key_gen()}"

    reg_key_data = {"user": user, 
                    "reg_key": key_hash,
                    "id": reg_key_id}

    if await cl_auth_db.upload_db_data(id=reg_key_id, data=reg_key_data) > 0:
        logger.info(f"Registration key generated for user '{user}':\n {key}")
    else:
        logger.error("Registration key gen failed...")
        


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a registration key for an umjiniti user.")
    parser.add_argument(
        '-u', '--user', 
        type=str, 
        help="Username to generate a registration key for"
    )
    args = parser.parse_args()

    asyncio.run(generate_registration_key(args.user))