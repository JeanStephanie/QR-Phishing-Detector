import time
import threading
import hashlib


class TTLCache:
    def __init__(self, default_ttl=3600, max_size=5000):
        self._store = {}
        self._lock = threading.Lock()
        self.default_ttl = default_ttl
        self.max_size = max_size

    def _purge_expired(self):
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if exp <= now]
        for k in expired:
            del self._store[k]

    def get(self, key):
        with self._lock:
            self._purge_expired()
            entry = self._store.get(key)
            if not entry:
                return None
            value, exp = entry
            if exp <= time.time():
                del self._store[key]
                return None
            return value

    def set(self, key, value, ttl=None):
        ttl = ttl or self.default_ttl
        with self._lock:
            if len(self._store) >= self.max_size:
                self._purge_expired()
                if len(self._store) >= self.max_size:
                    oldest = min(self._store, key=lambda k: self._store[k][1])
                    del self._store[oldest]
            self._store[key] = (value, time.time() + ttl)

    def delete(self, key):
        with self._lock:
            self._store.pop(key, None)


scan_cache = TTLCache(default_ttl=3600)
ssl_cache = TTLCache(default_ttl=6 * 3600)
whois_cache = TTLCache(default_ttl=24 * 3600)


def url_cache_key(url):
    return hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()


def file_cache_key(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()
