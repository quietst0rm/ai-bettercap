import requests
import logging
from src.config import CMD_URL, API_USER, API_PASS

def execute_command(cmd):
    """Sends a command to the Bettercap session."""
    try:
        response = requests.post(
            CMD_URL, 
            json={"cmd": cmd}, 
            auth=(API_USER, API_PASS),
            timeout=2
        )
        if response.status_code == 200:
            logging.info(f"Executed: {cmd}")
            return True
    except Exception as e:
        logging.error(f"Failed to execute command: {e}")
    return False

def mitigate_threat(ip_address):
    """
    Example Active Response:
    If an IP is malicious, we can use ARP banning to isolate it.
    """
    logging.warning(f"MITIGATION TRIGGERED: Isolating {ip_address}")
    execute_command(f"set arp.spoof.targets {ip_address}; arp.ban on")


class Responder:
    """Simple responder wrapper used by AnomalyDetector.

    The `respond` method accepts a dictionary payload and performs a mitigation
    action (or logs it). Keep implementation minimal for the template.
    """

    def respond(self, payload: dict) -> bool:
        ip = payload.get('src') or payload.get('ip')
        score = payload.get('score')
        logging.info(f"Responder invoked for {ip} score={score}")
        if not ip:
            return False
        try:
            mitigate_threat(ip)
            return True
        except Exception:
            logging.exception("Responder failed to mitigate")
            return False