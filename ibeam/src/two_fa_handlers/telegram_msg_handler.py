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

    def alert_admins(self, message):
        """For each admin in ADMIN_IDS, send a post request using urllib3 to alert them of the 2FA code"""
        for admin_id in TELEGRAM_ADMIN_IDS.split(","):
            try:
                requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                              json={'chat_id': admin_id, 'text': message})
            except Exception as exc:
                print(f"TELEGRAM FAULT: Could not post alert to telegram\nError Code: {exc}")

    def await_2fa_code(self) -> str:
        start_timestamp = time.time()
        # _LOGGER.info("Waiting for user response to 2FA prompt...")
        failed_attempts = []
        while True:
            updates = requests.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates").json()['result']
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
            time.sleep(1)


if __name__ == "__main__":
    TelegramMessageHandler().get_two_fa_code()
