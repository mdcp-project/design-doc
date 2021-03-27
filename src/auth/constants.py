import os

TIMEDELTA = os.getenv("REVOKE_TIME", 1440)
RBMQ_ADDRESS = os.getenv("RBMQ_ADDRESS")
QUEUE_NAME = os.getenv("QUEUE_NAME")
ENDPOINT = os.getenv("ENDPOINT", "localhost:5000")