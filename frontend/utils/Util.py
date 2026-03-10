import string
import random
import logging
from datetime import datetime, timedelta, timezone
import jwt
import uuid
import os

class Util:
    def __init__(self):
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

    def generate_ephemeral_token(self, user_id: str, user_rand: str,  secret_key: str) -> str:

        #local_tz = get_localzone()  
        now = datetime.now(tz=timezone.utc)
        
        payload = {
            'iss': f'https://{os.environ.get("SERVER_NAME")}/',
            'id': user_id,
            'rand': user_rand,
            'exp': now + timedelta(hours=8),
        }

        encoded_jwt = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")

        return encoded_jwt




