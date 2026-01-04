import os
import logging
import threading
import time
import pandas as pd
import numpy as np

from src.core.responder import Responder


class AnomalyDetector:
    """Simple streaming anomaly detector placeholder.

    Uses z-score over a rolling training buffer instead of heavier ML libs so
    the template runs without extra dependencies.
    """

    def __init__(self, min_samples: int = 10):
        self.training_buffer = []
        self.is_trained = False
        self.min_samples = min_samples
        self.mean = None
        self.std = None
        self.responder = Responder()
        # Buffered writer state
        self._write_buffer = []
        self._write_lock = threading.Lock()
        self._flush_interval = 1.0  # seconds
        self._max_batch = 100
        t = threading.Thread(target=self._writer_loop, daemon=True)
        t.start()

    def extract_features(self, event):
        try:
            data = event.get('data', {}) or {}

            # Bettercap net.sniff events vary by protocol. Support multiple shapes.
            # 1) Newer events sometimes include a nested 'packet' dict (raw packet)
            if 'packet' in data and isinstance(data['packet'], dict):
                pkt = data['packet']
                size = int(pkt.get('length', 0) or 0)
                is_tcp = 1 if 'tcp' in pkt else 0
                is_udp = 1 if 'udp' in pkt else 0
                dst_port = 0
                if is_tcp:
                    dst_port = int(pkt.get('tcp', {}).get('dst_port', 0) or 0)
                elif is_udp:
                    dst_port = int(pkt.get('udp', {}).get('dst_port', 0) or 0)
                return [size, is_tcp, is_udp, dst_port], pkt

            # 2) Simpler summary events (tcp/udp/dns/http) put a small 'data' dict
            if 'data' in data and isinstance(data['data'], dict):
                summary = data['data']
                size = int(summary.get('Size', 0) or 0)
                proto = data.get('protocol', '').lower()
                is_tcp = 1 if proto == 'tcp' else 0
                is_udp = 1 if proto == 'udp' else 0
                dst_port = 0
                # 'to' looks like 'ip:port' or 'ip:service'
                to_field = data.get('to', '')
                if ':' in to_field:
                    _, right = to_field.rsplit(':', 1)
                    if right.isdigit():
                        dst_port = int(right)
                    else:
                        # common service name mapping
                        svc_map = {'http': 80, 'https': 443, 'dns': 53}
                        dst_port = svc_map.get(right.lower(), 0)
                return [size, is_tcp, is_udp, dst_port], data
            return None, None
        except Exception:
            return None, None
    def process(self, event):
        features, raw_pkt = self.extract_features(event)
        if features is None:
            return

        if not self.is_trained:
            self.training_buffer.append(features)
            logging.debug(f"Buffered sample #{len(self.training_buffer)}")
            if len(self.training_buffer) >= self.min_samples:
                arr = np.array(self.training_buffer)
                self.mean = arr.mean(axis=0)
                self.std = arr.std(axis=0) + 1e-6
                self.is_trained = True
                self.training_buffer = []
                logging.info("AnomalyDetector: trained initial statistics")
            return

        vector = np.array(features)
        z = np.abs((vector - self.mean) / self.std)
        score = float(np.max(z))
        is_anomaly = bool(score > 3.0)

        self.log_to_db(features, score, is_anomaly)

        if is_anomaly:
            ip_src = raw_pkt.get('ipv4', {}).get('src', 'Unknown')
            logging.warning(f"ANOMALY DETECTED Source: {ip_src} score={score}")
            if ip_src != 'Unknown':
                try:
                    self.responder.respond({'src': ip_src, 'score': score})
                except Exception:
                    logging.exception("Responder failed")

    def log_to_db(self, features, score, is_anomaly):
        record = {
            'size': int(features[0]),
            'is_tcp': int(features[1]),
            'is_udp': int(features[2]),
            'dst_port': int(features[3]),
            'score': score,
            'is_anomaly': int(is_anomaly),
            'timestamp': pd.Timestamp.now()
        }
        # Buffer the record and let background writer flush it to disk
        with self._write_lock:
            self._write_buffer.append(record)
            buf_len = len(self._write_buffer)
        if buf_len >= self._max_batch:
            # signal immediate flush by calling writer once (it will pick up buffer)
            # we avoid extra threading primitives here for simplicity
            self._flush_buffer()

    def _writer_loop(self):
        while True:
            try:
                time.sleep(self._flush_interval)
                self._flush_buffer()
            except Exception:
                logging.exception("Buffered writer encountered an error")

    def _flush_buffer(self):
        # Atomically swap buffer
        with self._write_lock:
            if not self._write_buffer:
                return
            batch = list(self._write_buffer)
            self._write_buffer = []

        path = 'data/traffic_log.csv'
        os.makedirs(os.path.dirname(path), exist_ok=True)
        header = not os.path.exists(path)
        try:
            df = pd.DataFrame(batch)
            df.to_csv(path, mode='a', header=header, index=False)
            logging.info(f"Flushed {len(batch)} records to {path}")
        except Exception:
            logging.exception("Failed to flush buffered records to CSV")