from probe_mcp.ollamaproxy.utils.RedisDB import RedisDB
from utils.Util import Util
from uuid import uuid4
import asyncio
import argparse
import os
from passlib.hash import bcrypt

cl_auth_db = RedisDB(hostname=os.environ.get('CLIENT_AUTH_DB'), 
                     port=os.environ.get('CLIENT_AUTH_DB_PORT'))
util_obj = Util()


async def generate_registration_key(user: str):
    await cl_auth_db.connect_db()

    key = str(uuid4())
    key_hash = bcrypt.hash(key)
    reg_key_id = f"reg_key:{user}:{util_obj.key_gen()}"

    reg_key_data = {"user": user, 
                    "reg_key": key_hash,
                    "id": reg_key_id}

    if await cl_auth_db.upload_db_data(id=reg_key_id, data=reg_key_data) > 0:
        print("Registration key gen failed...")
    else:
        print(f"Registration key generated for user '{user}':\n {key}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a registration key for an umjiniti user.")
    parser.add_argument(
        '-u', '--user', 
        type=str, 
        help="Username to generate a registration key for"
    )
    args = parser.parse_args()

    asyncio.run(generate_registration_key(args.user))