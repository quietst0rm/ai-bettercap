import asyncio
import logging
from src.core.connector import BettercapConnector
from src.analysis.model import AnomalyDetector

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def main():
    # Queue to hold packets between Connector and Analyzer
    packet_queue = asyncio.Queue()
    
    # Initialize Modules
    connector = BettercapConnector(packet_queue)
    detector = AnomalyDetector()

    # Create Worker Tasks
    conn_task = asyncio.create_task(connector.connect())
    
    logging.info("Sentinel AI Engine Started.")
    
    # Main Processing Loop
    while True:
        event = await packet_queue.get()
        detector.process(event)
        packet_queue.task_done()

if __name__ == "__main__":
    asyncio.run(main())