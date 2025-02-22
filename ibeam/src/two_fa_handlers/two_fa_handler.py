from abc import ABC, abstractmethod
from typing import Union


class TwoFaHandler(ABC):

    @abstractmethod
    def get_two_fa_code(self, challenge_string: str = None) -> Union[str, None]:
        raise NotImplementedError()

    def __str__(self):
        return "TwoFaHandler()"
