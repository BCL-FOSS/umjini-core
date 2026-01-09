import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib
from aiosmtplib import SMTPException
import logging
from typing import Optional, Iterable
from quart import jsonify

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class EmailAlert:
    def __init__(self, host: str, port: int, username: str, password: str, sender: str, tls: bool = True, timeout: int = 10):
        self.smtp_host = host
        self.smtp_port = int(port) 
        self.username = username
        self.password = password
        self.sender = sender
        self.tls = tls
        self.timeout = timeout

    async def send_email_alert(
        self,
        recipient: str,
        subject: str,
        message: str
    ):
        if not self.smtp_host or not self.smtp_port:
            logger.error("SMTP host/port not configured")
            return None

        msg = MIMEMultipart()
        msg["From"] = self.sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        use_tls = False
        start_tls = False
        if self.tls:
            if self.smtp_port == 465:
                use_tls = True
            else:
                start_tls = True

        smtp = aiosmtplib.SMTP(
            hostname=self.smtp_host,
            port=self.smtp_port,
            timeout=self.timeout,
            use_tls=use_tls,
            start_tls=start_tls
        )

        try:

            logger.debug(f"Sending email from {self.sender} to {recipient}")
            result = await smtp.send_message(msg, sender=self.sender, recipients=[recipient], username=self.username, password=self.password)
            logger.info(f"Email send result: {result}")

            await smtp.quit()
            return result

        except SMTPException as smtp_e:
            logger.exception(f"SMTP error occurred while sending email: {smtp_e}")
            return None
        except Exception as e:
            logger.exception(f"Failed to send email: {e}")
            return None
