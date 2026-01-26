import uuid
import string
import random
import logging
import uuid
import aiohttp
from datetime import datetime, timedelta
from tzlocal import get_localzone
import jwt
import uuid
import re
from wtforms.validators import ValidationError
import string
import random
import logging
import os
from pathlib import Path
import asyncio
import secrets
from quart import (send_file)
import shutil
import os
import uuid
from pathlib import Path
import zipfile
import aiohttp
from datetime import datetime, timedelta
import secrets
from zoneinfo import ZoneInfo
from tzlocal import get_localzone
import jwt

class Util:
    def __init__(self):
        self.umj_api_conn_session = aiohttp.ClientSession()
        self.logger = logging.getLogger(__name__)
        self.company_global_namespace = 'cmp:'
        self.company_data_global_namespace = 'dta:'
        self.user_global_namespace = 'usr:'
        self.user_id_global_namespace = 'uid:'
        
    def gen_id(self) -> str:
        return str(uuid.uuid4())

    def gen_user(self, username=""):
        user_namespace = f'{self.user_global_namespace}{self.gen_id()}'
        user_id = f'{self.user_id_global_namespace}{username}{self.gen_id()}'

        return user_namespace, user_id
    
    def key_gen(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.SystemRandom().choice(chars) for _ in range(size))
    
    def generate_api_key(self) -> str:
        return str(uuid.uuid4())
    
    async def make_async_request(self, cmd: str, url: str, payload: dict, headers={'Content-Type':'application/json'}):
        async with self.umj_api_conn_session as session:
            try:
                async with session.request(method=cmd, url=url, headers=headers, json=payload) as response:
                            if response.status == 200:
                                data = await response.json()
                                return data
                            else:
                                response.close()
                                return response.status
            except aiohttp.ClientError as e:
                response.close()
                return {"error": str(e), "status_code": 500}
            except Exception as error:
                response.close()
                return {"error": str(error)}
            finally:
                response.close()

    def generate_ephemeral_token(self, user_id: str, user_rand: str,  secret_key: str) -> str:

        local_tz = get_localzone()  
        now = datetime.now(local_tz)
        
        payload = {
            'iss': 'https://baughcl.com/',
            'id': user_id,
            'rand': user_rand,
            'exp': now + timedelta(hours=8),
        }

        encoded_jwt = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")

        return encoded_jwt




