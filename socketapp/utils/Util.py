import uuid
import re
from wtforms.validators import ValidationError
import string
import random
from quart import flash
import logging
import os
import sys
from pathlib import Path
import subprocess
import asyncio
from quart import (flash, redirect, url_for)
import logging
import os
import jwt
from datetime import datetime, timedelta, timezone
from tzlocal import get_localzone
import jwt

class Util:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_ephemeral_token(self, id: str, rand: str,  secret_key: str, expire: int = 3) -> str:

        local_tz = get_localzone()  
        now = datetime.now(tz=timezone.utc)
        
        payload = {
            'iss': 'https://baughcl.tech/',
            'id': id,
            'rand': rand,
            'exp': now + timedelta(hours=expire),
        }

        encoded_jwt = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")

        return encoded_jwt
    
    def generate_api_key(self) -> str:
        return str(uuid.uuid4())
    
    def key_gen(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.SystemRandom().choice(chars) for _ in range(size))


        
    


    
        
        
        
        




