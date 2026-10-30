"""Queue package for LogMorph."""

from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer

__all__ = ["LogMorphKafkaProducer", "get_kafka_producer"]
