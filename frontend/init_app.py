from quart import Quart
import secrets
from quart_wtf.csrf import CSRFProtect
from quart_auth import (
    QuartAuth)
import nest_asyncio
from werkzeug.local import LocalProxy
import logging
from accounts.Client import Client
from accounts.Admin import Admin
import os
from quart_rate_limiter import (RateLimiter, RateLimit, timedelta)

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

app = Quart(__name__)
app.config.from_object("config")
app.config['SECRET_KEY'] = secrets.token_urlsafe()
app.config['SECURITY_PASSWORD_SALT'] = str(secrets.SystemRandom().getrandbits(128))

# Trust Proxy Headers (IMPORTANT for reverse proxy)
app.config["PREFERRED_URL_SCHEME"] = "https"
app.config["SERVER_NAME"] = os.environ.get('SERVER_NAME')
app.config["WTF_CSRF_HEADERS"] = ["X-Forwarded-For", "X-Forwarded-Proto"]

# Authentication salts for user & admin accounts
auth_salts = {
    "client": str(secrets.SystemRandom().getrandbits(128)),
    "admin": str(secrets.SystemRandom().getrandbits(128)),
}

# Authentication configs for user & admin accounts
auth_configs = {
    "client": {
        "attribute_name": "client",
        "cookie_name": "CLIENT",
        "salt": auth_salts["client"],
    },
    "admin": {
        "attribute_name": "admin",
        "cookie_name": "ADMIN",
        "salt": auth_salts["admin"],
    },
}

# Create Quart-Auth user and admin account types
for key, config in auth_configs.items():
    if key == "admin":
        admin_auth = QuartAuth(
            app,
            attribute_name=config["attribute_name"],
            cookie_name=config["cookie_name"],
            salt=config["salt"],
            singleton=False,
        )
        admin_auth.user_class=Admin

    if key == "client":
        client_auth = QuartAuth(
            app,
            attribute_name=config["attribute_name"],
            cookie_name=config["cookie_name"],
            salt=config["salt"],
            singleton=False,
        )
        client_auth.user_class=Client

# Generate current client & admin variables for umjiniti authentication control
current_client = LocalProxy(lambda: client_auth.load_user())
current_admin = LocalProxy(lambda: admin_auth.load_user())

nest_asyncio.apply()

RateLimiter(
    app,
    default_limits=[
        RateLimit(5, timedelta(seconds=1)),
        RateLimit(100, timedelta(minutes=1)),
    ],
)

csrf = CSRFProtect()
csrf.init_app(app=app)

