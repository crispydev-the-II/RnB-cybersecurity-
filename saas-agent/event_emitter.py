"""
event_emitter.py
Simple pub/sub event emitter for cross-stage communication.
Stages call emit(event_type, data) to send events.
Dashboard subscribes with on(event_type, callback).
"""

import threading
from collections import defaultdict
from datetime import datetime

class EventEmitter:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self):
        self._listeners = defaultdict(list)  # event_type -> [callbacks]
        self._history = []                  # all events for replay
        self._lock = threading.Lock()
        self._event_count = defaultdict(int)  # count per event type

    def on(self, event_type, callback):
        """Subscribe to an event. Callback receives (event_type, data)."""
        with self._lock:
            self._listeners[event_type].append(callback)

    def off(self, event_type, callback):
        """Unsubscribe from an event."""
        with self._lock:
            if callback in self._listeners[event_type]:
                self._listeners[event_type].remove(callback)

    def emit(self, event_type, data=None):
        """Emit an event to all subscribers."""
        if data is None:
            data = {}

        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        }

        with self._lock:
            self._history.append(event)
            self._event_count[event_type] += 1
            listeners = list(self._listeners.get(event_type, []))
            all_listeners = list(self._listeners.get("*", []))

        for callback in listeners + all_listeners:
            try:
                callback(event_type, data)
            except Exception:
                pass

    def get_history(self, event_type=None):
        """Get all events, optionally filtered by type."""
        with self._lock:
            if event_type:
                return [e for e in self._history if e["type"] == event_type]
            return list(self._history)

    def get_counts(self):
        """Get event type counts."""
        with self._lock:
            return dict(self._event_count)

    def clear(self):
        """Clear all history and reset counts."""
        with self._lock:
            self._history.clear()
            self._event_count.clear()


# Convenience singleton
_emitter = None

def get_emitter():
    global _emitter
    if _emitter is None:
        _emitter = EventEmitter()
    return _emitter

def emit(event_type, data=None):
    get_emitter().emit(event_type, data)

def on(event_type, callback):
    get_emitter().on(event_type, callback)

def off(event_type, callback):
    get_emitter().off(event_type, callback)
