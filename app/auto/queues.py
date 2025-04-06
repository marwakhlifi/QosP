from queue import Queue

def create_iperf_queue():
    """Crée une file thread-safe pour les résultats iPerf"""
    return Queue()