import logging
import os
from pathlib import Path
import time
from typing import Union

from ibeam.src.two_fa_handlers.two_fa_handler import TwoFaHandler

import requests

_LOGGER = logging.getLogger('ibeam.' + Path(__file__).stem)

TELEGRAM_BOT_TOKEN = os.environ.get('IBEAM_TELEGRAM_BOT_TOKEN', None)
"""Telegram bot token used for the telegram 2FA handler"""

TELEGRAM_ADMIN_IDS = os.environ.get('IBEAM_TELEGRAM_ADMIN_IDS', None)
"""A no-space comma-separated list of telegram user admin ids (e.g. 123456789,987654321)"""

BASE_PROMPT_MSG = "The IBKR Gateway requires a new 2FA code."
MAXIMUM_RETRIES = 5
AWAIT_TIMEOUT = 43200  # 12 hours
POLLING_INTERVAL = 2


class TelegramMessageHandler(TwoFaHandler):
    def get_two_fa_code(self, challenge_string: str = None) -> Union[str, None]:
        message = BASE_PROMPT_MSG
        if challenge_string is not None:
            message += f"\nChallenge: {challenge_string}"
        else:
            message += "\nNo challenge provided."
        message += "\n\nPlease send the 2FA code in the following format:\nCode: 12345678"
        self.alert_admins(message)
        return self.await_2fa_code()

    def http_request(self, _type: str, url: str, data: dict = None, _try: int = 1, retry_delay: float = 1) -> dict:
        """Attempt to make an http request to the given url. If the request fails, retry with recursion"""
        if _try > MAXIMUM_RETRIES:
            raise ConnectionError(f"Could not connect to Telegram API after 5 attempts with url: {url}")

        if _type == 'GET':
            r = requests.get(url, params=data if data is not None else {})
        elif _type == 'POST':
            r = requests.post(url, json=data if data is not None else {})
        else:
            raise ValueError(f"Invalid http request type: {_type} (must be GET or POST)")

        if r.status_code == 200:
            return r.json()
        elif r.status_code == 500:
            # Specific condition for the Google Cloud service being used
            _LOGGER.error(f"Internal server error (500) thrown when attempting to {_type} to Telegram API - "
                          f"{retry_delay} second delay before retrying (attempt {_try})")
            # Quick exponential retry delay without incrementing the retry count
            time.sleep(retry_delay)
            return self.http_request(_type, url, data, _try, retry_delay * 1.1)
        else:
            # General condition for other errors - Exponential retry delay before retrying
            _LOGGER.error(f"Telegram API returned an error code: {r.status_code, r.text} - "
                          f"{retry_delay} second delay before retrying (attempt {_try}/{MAXIMUM_RETRIES})")
            time.sleep(retry_delay)

        return self.http_request(_type, url, data, _try + 1, retry_delay * 1.5)

    def alert_admins(self, message):
        """For each admin in ADMIN_IDS, send a post request using urllib3 to alert them of the 2FA code request"""
        for admin_id in TELEGRAM_ADMIN_IDS.split(","):
            self.http_request('POST', f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
                              {'chat_id': admin_id, 'text': message})

    def await_2fa_code(self) -> str:
        """Awaits the 2FA code response from either of the admins - provided in os.getenv('IBEAM_TELEGRAM_ADMIN_IDS')"""
        start_timestamp = time.time()
        failed_attempts = []
        while True:
            if time.time() >= (AWAIT_TIMEOUT + start_timestamp):
                raise TimeoutError(f"Timed out after {AWAIT_TIMEOUT} seconds waiting for 2FA code response")

            updates = self.http_request('GET', f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates')['result']
            for update in updates:
                upd_id = update['update_id']
                timestamp = update['message']['date']
                message = update['message']['text']

                if (upd_id not in failed_attempts) and (timestamp > start_timestamp) and ("code:" in message.lower()):
                    try:
                        code = message.lower().strip().replace(" ", "").split("code:")[1]
                        _LOGGER.info(f"Received 2FA code from Telegram handler: {code}")
                        self.alert_admins(f"Sending 2FA code to API: {code}")
                        return code
                    except:
                        failed_attempts.append(upd_id)
                        self.alert_admins("Could not parse code from message.\nPlease use the following format:"
                                          "\nCODE: 12345678")
            time.sleep(POLLING_INTERVAL)
