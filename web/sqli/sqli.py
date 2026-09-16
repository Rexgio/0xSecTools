from dataclasses import dataclass
from typing import Any


@dataclass
class SQLITestResult:
    vulnerable: bool
    technique: str
    status_code: int | None
    response_time: float | None
    evidence: str


class SQLI:
    def __init__(self, url: str):
        self.url = url

    def request(self, params: dict[str, Any]) -> SQLITestResult:
        raise NotImplementedError
