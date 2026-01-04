import asyncio
import aiohttp
import json
import os
import logging
import base64
from src.config import API_URL, API_USER, API_PASS


class BettercapConnector:
    def __init__(self, data_queue):
        self.data_queue = data_queue
        auth = base64.b64encode(f"{API_USER}:{API_PASS}".encode()).decode()
        self.headers = {"Authorization": f"Basic {auth}"}
        self._sample_logged = False
        self._tcp_sample_logged = False

    async def connect(self):
        # Use aiohttp websocket client which accepts headers cleanly
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    logging.info(f"Connecting to Bettercap at {API_URL}...")
                    async with session.ws_connect(API_URL, headers=self.headers) as ws:
                        logging.info("Connected to Sensor.")
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                try:
                                    event = json.loads(msg.data)
                                except Exception:
                                    continue
                                logging.debug(f"Received message: {msg.data[:200]}")
                                tag = event.get('tag')
                                logging.info(f"Event tag={tag}")
                                if isinstance(tag, str) and tag.startswith('net.sniff'):
                                    # Log one sample event structure to help map fields
                                    if not self._sample_logged:
                                        try:
                                            # persist one sample event to disk for offline inspection
                                            sample_path = '/app/data/sample_event.json'
                                            os.makedirs('/app/data', exist_ok=True)
                                            with open(sample_path, 'w') as f:
                                                f.write(json.dumps(event))
                                            logging.info(f"Wrote sample event to {sample_path}")
                                        except Exception:
                                            logging.exception("Failed to write sample event")
                                        self._sample_logged = True
                                    # also persist a TCP sample if available for packet inspection
                                    if ('tcp' in tag) and (not self._tcp_sample_logged):
                                        try:
                                            sample_tcp = '/app/data/sample_tcp.json'
                                            with open(sample_tcp, 'w') as f:
                                                f.write(json.dumps(event))
                                            logging.info(f"Wrote TCP sample event to {sample_tcp}")
                                        except Exception:
                                            logging.exception("Failed to write tcp sample")
                                        self._tcp_sample_logged = True
                                    # Queue events that contain either a raw 'packet' payload
                                    # or a summarized 'data' dict (many sensors emit small
                                    # summary objects with Size/protocol/to fields).
                                    data = event.get('data', {}) or {}
                                    queued = False
                                    if isinstance(data, dict) and 'packet' in data:
                                        await self.data_queue.put(event)
                                        queued = True
                                    elif isinstance(data, dict) and isinstance(data.get('data', None), dict):
                                        # summary event (e.g. tcp with Size)
                                        await self.data_queue.put(event)
                                        queued = True
                                    if queued:
                                        logging.info("Queued net.sniff event")
                                    else:
                                        logging.debug("Skipping net.sniff event without usable payload")
                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                logging.error("Websocket error, reconnecting")
                                break
                except Exception as e:
                    logging.error(f"Connection error: {e}. Retrying in 5s...")
                    await asyncio.sleep(5)