# Gunicorn configuration settings.
import multiprocessing

#bind = ":8080"
# Don't start too many workers:
workers = multiprocessing.cpu_count() + 2
worker_connections = 50000
# Give workers an expiry:
max_requests = 100000
max_requests_jitter = 5000
preload_app = True
# Set longer timeout for workers
timeout = 180
# Disable access logging.
accesslog = None
