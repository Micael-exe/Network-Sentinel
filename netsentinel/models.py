from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    ports: Optional[List[Port]] = None  # None = portas não foram varridas
