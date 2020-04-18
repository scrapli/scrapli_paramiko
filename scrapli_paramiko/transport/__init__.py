"""scrapli_paramiko.transport"""
from scrapli_paramiko.transport.miko import MIKO_TRANSPORT_ARGS as TRANSPORT_ARGS
from scrapli_paramiko.transport.miko import MikoTransport as Transport

__all__ = (
    "Transport",
    "TRANSPORT_ARGS",
)
