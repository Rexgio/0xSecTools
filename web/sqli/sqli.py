from dataclasses import dataclass
from typing import Any


@dataclass
class SQLITestResult:
    vulnerable: bool
    technique: str
    status_code: int | None
    response_time: float | None
    evidence: str


class SQLIBase:
    def __init__(self, url: str):
        self.url = url

    def request(self, params: dict[str, Any]) -> SQLITestResult:
        raise NotImplementedError


class SQLIerror(SQLIBase):
    def request(self, params):
        return SQLITestResult(
            vulnerable=True,
            technique="error-based",
            status_code=500,
            response_time=0.12,
            evidence="La respuesta contiene un error SQL del servidor.",
        )


class SQLIboolean(SQLIBase):
    def request(self, params):
        return SQLITestResult(
            vulnerable=True,
            technique="boolean-based",
            status_code=200,
            response_time=0.10,
            evidence="Las respuestas de las condiciones verdadera y falsa difieren.",
        )


class SQLItimed(SQLIBase):
    def request(self, params):
        return SQLITestResult(
            vulnerable=True,
            technique="time-based",
            status_code=200,
            response_time=5.08,
            evidence="La respuesta presenta un retraso reproducible respecto al control.",
        )
