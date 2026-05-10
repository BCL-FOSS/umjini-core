import argparse
import asyncio
import json
import sys
from passlib.hash import bcrypt
from init_app import util_obj, logger
from app import cl_auth_db

async def register_user(username: str, password: str, email: str, fname: str, lname: str) -> None:
    username = username.replace(" ", "").lower()
    password_hash = bcrypt.hash(password)
    logger.info(f"Registering user: {username}")
    user_nmp, user_id = util_obj.gen_user(username=username)
    user_obj = {
        "id": user_id,
        "unm": username,
        "eml": email,
        "pwd": password_hash,
        "fname": fname,
        "lname": lname,
    }
    user_key = f"{user_nmp}:{user_id}"
    user_obj["db_id"] = user_key
    uploaded = await cl_auth_db.upload_db_data(id=user_key, data=user_obj)
    if uploaded > 0:
        logger.info(f"Registration successful for '{username}'.")
    else:
        logger.error(f"DB upload failed for user '{username}'.")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Register a new user account from the command line."
    )
    parser.add_argument("-u", "--username", required=True,  help="Desired username")
    parser.add_argument("-p", "--password", required=True,  help="Account password")
    parser.add_argument("-e", "--email",    required=True,  help="Email address")
    parser.add_argument("-f", "--fname",    required=True,  help="First name")
    parser.add_argument("-l", "--lname",    required=True,  help="Last name")
    args = parser.parse_args()
    asyncio.run(register_user(
        username=args.username,
        password=args.password,
        email=args.email,
        fname=args.fname,
        lname=args.lname,
    ))