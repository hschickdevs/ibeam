import logging
import os
import sys
import time
import json
from getpass import getpass

from pathlib import Path
from typing import Optional

from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

from ibeam.src import var
from ibeam.src.authenticate import authenticate_gateway
from ibeam.src.http_handler import HttpHandler
from ibeam.src.inputs_handler import InputsHandler
from ibeam.src.process_utils import find_procs_by_name, start_gateway
from ibeam.src.two_fa_handlers.two_fa_handler import TwoFaHandler

sys.path.insert(0, str(Path(__file__).parent.parent))

from ibeam import config

config.initialize()

_LOGGER = logging.getLogger('ibeam.' + Path(__file__).stem)


class GatewayClient():

    def __init__(self,
                 http_handler: HttpHandler,
                 inputs_handler: InputsHandler,
                 two_fa_handler: TwoFaHandler,
                 account: str = None,
                 password: str = None,
                 key: str = None,
                 gateway_dir: str = None,
                 driver_path: str = None,
                 base_url: str = None):

        self.base_url = base_url if base_url is not None else var.GATEWAY_BASE_URL

        self.account = account if account is not None else os.environ.get('IBEAM_ACCOUNT')
        """IBKR account name."""

        self.password = password if password is not None else os.environ.get('IBEAM_PASSWORD')
        """IBKR password."""

        self.key = key if key is not None else os.environ.get('IBEAM_KEY')
        """Key to the IBKR password."""

        if self.account is None:
            self.account = input('Account: ')

        if self.password is None:
            self.password = getpass('Password: ')
            if self.key is None:
                self.key = getpass('Key: ') or None

        self.gateway_dir = gateway_dir
        self.driver_path = driver_path

        self.http_handler = http_handler
        self.inputs_handler = inputs_handler
        self.two_fa_handler = two_fa_handler

        self._concurrent_maintenance_attempts = 1

    def try_starting(self) -> Optional[int]:
        processes = find_procs_by_name(var.GATEWAY_PROCESS_MATCH)
        if not processes:
            _LOGGER.info('Gateway not found, starting new one...')

            start_gateway(self.gateway_dir)

            time.sleep(1)  # buffer to ensure process is running

            processes = find_procs_by_name(var.GATEWAY_PROCESS_MATCH)
            success = len(processes) != 0
            if not success:
                return None

            self.server_process = processes[0].pid
            _LOGGER.info(f'Gateway started with pid: {self.server_process}')

            # let's try to communicate with the Gateway
            t_end = time.time() + var.GATEWAY_STARTUP
            ping_success = False
            while time.time() < t_end:
                status = self.http_handler.try_request(self.base_url, False)
                if not status[0]:
                    seconds_remaining = round(t_end - time.time())
                    if seconds_remaining > 0:
                        _LOGGER.debug(
                            f'Cannot ping Gateway. Retrying for another {seconds_remaining} seconds')
                        time.sleep(1)
                else:
                    _LOGGER.debug('Gateway connection established')
                    ping_success = True
                    break

            if not ping_success:
                _LOGGER.error('Gateway process found but cannot establish a connection with the Gateway')

        return processes[0].pid

    def _authenticate(self) -> (bool, bool):
        return authenticate_gateway(driver_path=self.driver_path,
                                    account=self.account,
                                    password=self.password,
                                    key=self.key,
                                    base_url=self.base_url,
                                    two_fa_handler=self.two_fa_handler)

    # def _reauthenticate(self):
    #     self._try_request(self.base_url + _ROUTE_REAUTHENTICATE, False)

    def try_authenticating(self, request_retries=var.REQUEST_RETRIES) -> (bool, bool):
        status = self.get_status(max_attempts=request_retries)
        if status[2]:  # running and authenticated
            return True, False
        elif not status[0]:  # no gateway running
            _LOGGER.error('Cannot communicate with the Gateway. Consider increasing IBEAM_GATEWAY_STARTUP')
            return False, False
        else:
            if status[1]:
                msg = 'Gateway session found but not authenticated, authenticating...'
                try:
                    msg += f" (Failure Reason: {self.get_auth_fail_reason()})"
                except:
                    # Accounts for unexpected issue (this feature is not necessary)
                    pass
                _LOGGER.info(msg)

                """
                Annoyingly this is an async request that takes arbitrary amount of time and returns no
                meaningful response. For now we stick with full login instead of calling reauthenticate. 
                """
                # self._reauthenticate()
            else:
                _LOGGER.info('No active sessions, logging in...')

            success, shutdown = self._authenticate()
            _LOGGER.info(f'Authentication process {"succeeded" if success else "failed"}')
            if shutdown:
                return False, True
            if not success:
                return False, False
            # self._try_request(self.base_url + _ROUTE_VALIDATE, False, max_attempts=REQUEST_RETRIES)

            time.sleep(3)  # buffer for session to be authenticated

            # double check if authenticated
            status = self.get_status(max_attempts=request_retries)
            if not status[2]:
                if status[1]:
                    _LOGGER.error('Gateway session active but not authenticated')
                elif status[0]:
                    _LOGGER.error('Gateway running but has no active sessions')
                else:
                    _LOGGER.error('Cannot communicate with the Gateway')
                return False, False

        return True, False

    def get_status(self, max_attempts=var.REQUEST_RETRIES) -> (bool, bool, bool):
        return self.http_handler.try_request(self.base_url + var.ROUTE_TICKLE, True, max_attempts=max_attempts)

    def get_auth_fail_reason(self) -> str:
        try:
            r = json.loads(self.http_handler.url_request(self.base_url + var.ROUTE_AUTH_STATUS).read().decode('utf8'))
            return r["fail"]
        except Exception as e:
            _LOGGER.error(f'Failed to get auth failure reason: {e}')
            return "None"

    def validate(self) -> bool:
        return self.http_handler.try_request(self.base_url + var.ROUTE_VALIDATE, False)[1]

    def tickle(self) -> bool:
        return self.http_handler.try_request(self.base_url + var.ROUTE_TICKLE, True)[0]

    def user(self):
        try:
            response = self.http_handler.url_request(self.base_url + var.ROUTE_USER)
            _LOGGER.info(response.read())
        except Exception as e:
            _LOGGER.exception(e)

    def start_and_authenticate(self, request_retries=2) -> (bool, bool):
        """
        Starts the gateway and authenticates using the credentials stored.
        Gets 2 retries only since this is the initial gateway startup sequence.
        """

        self.try_starting()

        success, shutdown = self.try_authenticating(request_retries=request_retries)

        return success, shutdown

    def build_scheduler(self):
        if var.SPAWN_NEW_PROCESSES:
            executors = {'default': ProcessPoolExecutor(self._concurrent_maintenance_attempts)}
        else:
            executors = {'default': ThreadPoolExecutor(self._concurrent_maintenance_attempts)}
        job_defaults = {'coalesce': False, 'max_instances': self._concurrent_maintenance_attempts}
        self._scheduler = BlockingScheduler(executors=executors, job_defaults=job_defaults, timezone='UTC')
        self._scheduler.add_job(self._maintenance, trigger=IntervalTrigger(seconds=var.MAINTENANCE_INTERVAL))

    def maintain(self):
        self.build_scheduler()
        _LOGGER.info(f'Starting maintenance with interval {var.MAINTENANCE_INTERVAL} seconds')
        self._scheduler.start()

    def _maintenance(self):
        _LOGGER.debug('Maintenance')

        success, shutdown = self.start_and_authenticate(request_retries=var.REQUEST_RETRIES)

        if shutdown:
            _LOGGER.warning('Shutting IBeam maintenance down due to exceeded number of failed attempts.')
            self._scheduler.remove_all_jobs()
            self._scheduler.shutdown(False)
        elif success:
            _LOGGER.info('Gateway running and authenticated')

    def kill(self) -> bool:
        processes = find_procs_by_name(var.GATEWAY_PROCESS_MATCH)
        if processes:
            processes[0].terminate()

            time.sleep(1)

            # double check we succeeded
            processes = find_procs_by_name(var.GATEWAY_PROCESS_MATCH)
            if processes:
                return False

        return True

    def __getstate__(self):
        state = self.__dict__.copy()

        # APS schedulers can't be pickled
        del state['_scheduler']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.build_scheduler()
