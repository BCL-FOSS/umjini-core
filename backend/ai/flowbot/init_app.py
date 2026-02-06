from quart import Quart
import logging

logging.basicConfig(level=logging.INFO)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

app = Quart(__name__)