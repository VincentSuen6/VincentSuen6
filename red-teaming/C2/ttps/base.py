from abc import ABC, abstractmethod
from typing import Tuple


class BaseTTP(ABC):
    """
    Every TTP module must implement run() and return a 3-tuple:
        status    — "success" | "failed"
        output    — human-readable result string
        telemetry — structured dict captured for the Frida/Sigma comparison stage
    """

    @abstractmethod
    def run(self, params: dict) -> Tuple[str, str, dict]:
        ...
