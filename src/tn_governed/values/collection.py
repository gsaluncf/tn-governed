"""Bulk passes that build many long-lived objects pause the cycle collector.

Reference counting still frees objects during the pass. Only the cycle
collector waits, so it does not rescan objects the pass keeps until it ends.
"""

import gc
from contextlib import contextmanager
from functools import wraps


@contextmanager
def collection_paused():
    enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if enabled:
            gc.enable()


def pauses_collection(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        with collection_paused():
            return function(*args, **kwargs)
    return wrapper
