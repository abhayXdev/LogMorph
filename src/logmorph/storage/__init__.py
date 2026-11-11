"""Log storage adapters and persistence layer."""

from logmorph.storage.adapter import (
    PostgresStorageAdapter,
    get_storage_adapter,
    log_event_to_record,
    record_to_event_detail,
    record_to_event_item,
    record_to_read,
)

__all__ = [
    "PostgresStorageAdapter",
    "get_storage_adapter",
    "log_event_to_record",
    "record_to_event_detail",
    "record_to_event_item",
    "record_to_read",
]
