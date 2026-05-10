from quart import Quart
import nest_asyncio
import logging
import secrets
import nest_asyncio
import logging
from quart_rate_limiter import (RateLimiter, RateLimit, timedelta)
import logging
from ai.smartbot.utils.Util import Util

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

app = Quart(__name__)
app.config.from_object("config")
app.config['SECRET_KEY'] = secrets.token_urlsafe()
app.config['SECURITY_PASSWORD_SALT'] = str(secrets.SystemRandom().getrandbits(128))
nest_asyncio.apply()
RateLimiter(
    app,
    default_limits=[
        RateLimit(1, timedelta(seconds=1)),
        RateLimit(20, timedelta(minutes=1)),
    ],
)
util_obj = Util()
