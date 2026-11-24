"""Comprehensive test suite for LogMorph Python SDK."""

import json
import logging
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from logmorph import LogMorph, LogMorphHandler


class TestLogMorphClientInit(unittest.TestCase):
    """Test client initialization and validation."""

    def test_init_success_with_defaults(self):
        client = LogMorph(api_key="lm_live_testkey123", auto_start=False)
        self.assertEqual(client.api_key, "lm_live_testkey123")
        self.assertEqual(client.endpoint, "https://logmorph.onrender.com/api/v1/ingest")
        self.assertEqual(client.source, "default")
        self.assertEqual(client.batch_size, 25)
        self.assertEqual(client.flush_interval, 1.0)
        self.assertEqual(client.max_buffer_size, 1000)
        client.close()

    def test_init_custom_parameters(self):
        client = LogMorph(
            api_key="  lm_live_customkey  ",
            endpoint="https://custom.endpoint.com/ingest/",
            source="my-service",
            batch_size=50,
            flush_interval=0.5,
            max_buffer_size=500,
            timeout=3.0,
            auto_start=False,
        )
        self.assertEqual(client.api_key, "lm_live_customkey")
        self.assertEqual(client.endpoint, "https://custom.endpoint.com/ingest")
        self.assertEqual(client.source, "my-service")
        self.assertEqual(client.batch_size, 50)
        self.assertEqual(client.flush_interval, 0.5)
        self.assertEqual(client.max_buffer_size, 500)
        self.assertEqual(client.timeout, 3.0)
        client.close()

    def test_init_raises_on_empty_key(self):
        with self.assertRaises(ValueError):
            LogMorph(api_key="", auto_start=False)
        with self.assertRaises(ValueError):
            LogMorph(api_key="   ", auto_start=False)
        with self.assertRaises(ValueError):
            LogMorph(api_key=None, auto_start=False)  # type: ignore


class TestLogMorphQueueAndFormatting(unittest.TestCase):
    """Test message formatting and queueing semantics."""

    def setUp(self):
        self.client = LogMorph(
            api_key="lm_live_test",
            max_buffer_size=10,
            auto_start=False,
        )

    def tearDown(self):
        self.client.close()

    def test_log_string_message(self):
        res = self.client.log("Simple plain text log message")
        self.assertTrue(res)
        self.assertEqual(self.client._queue.qsize(), 1)
        item = self.client._queue.get_nowait()
        self.assertEqual(item, "Simple plain text log message")

    def test_log_dict_message_with_level(self):
        res = self.client.log({"event": "user_login", "user_id": 42}, level="INFO")
        self.assertTrue(res)
        item = self.client._queue.get_nowait()
        parsed = json.loads(item)
        self.assertEqual(parsed["event"], "user_login")
        self.assertEqual(parsed["user_id"], 42)
        self.assertEqual(parsed["level"], "INFO")

    def test_log_extra_kwargs_merged(self):
        res = self.client.log(
            {"message": "Query executed"},
            level="DEBUG",
            latency_ms=12.4,
            db="postgres",
        )
        self.assertTrue(res)
        item = self.client._queue.get_nowait()
        parsed = json.loads(item)
        self.assertEqual(parsed["message"], "Query executed")
        self.assertEqual(parsed["level"], "DEBUG")
        self.assertEqual(parsed["latency_ms"], 12.4)
        self.assertEqual(parsed["db"], "postgres")

    def test_queue_overflow_drops_oldest(self):
        """Bounded buffer must never exceed max_buffer_size or block indefinitely."""
        for i in range(15):
            self.client.log(f"log_{i}")

        self.assertEqual(self.client._queue.qsize(), 10)
        first_item = self.client._queue.get_nowait()
        # Oldest items (0-4) should have been dropped
        self.assertEqual(first_item, "log_5")


class TestLogMorphDispatch(unittest.TestCase):
    """Test background network dispatch and batching."""

    @patch("urllib.request.urlopen")
    def test_single_log_dispatch(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "accepted", "event_id": "evt_123"}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        client = LogMorph(
            api_key="lm_live_secret",
            endpoint="https://logmorph.onrender.com/api/v1/ingest",
            source="test-source",
            flush_interval=0.1,
            batch_size=10,
        )

        client.log("Single event line")
        flushed = client.flush(timeout=2.0)
        client.close()

        self.assertTrue(flushed)
        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://logmorph.onrender.com/api/v1/ingest")
        self.assertEqual(req.headers["X-api-key"], "lm_live_secret")
        self.assertEqual(req.headers["Content-type"], "application/json")

        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["raw_log"], "Single event line")
        self.assertEqual(payload["source"], "test-source")

    @patch("urllib.request.urlopen")
    def test_batch_log_dispatch(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "accepted", "count": 3}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        client = LogMorph(
            api_key="lm_live_secret",
            endpoint="https://logmorph.onrender.com/api/v1/ingest",
            source="batch-source",
            flush_interval=0.1,
            batch_size=5,
        )

        for i in range(3):
            client.log(f"Batch event {i}")

        flushed = client.flush(timeout=2.0)
        client.close()

        self.assertTrue(flushed)
        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://logmorph.onrender.com/api/v1/ingest/batch")

        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(len(payload["logs"]), 3)
        self.assertEqual(payload["source"], "batch-source")
        self.assertEqual(payload["logs"][0], "Batch event 0")


class TestLogMorphResilience(unittest.TestCase):
    """Test fail-safe behavior when the network or backend fails."""

    @patch("urllib.request.urlopen")
    def test_http_error_does_not_raise(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=500,
            msg="Internal Server Error",
            hdrs={},  # type: ignore
            fp=None,
        )

        client = LogMorph(
            api_key="lm_live_secret",
            flush_interval=0.05,
        )

        # Must not raise an exception
        client.log("Error event")
        flushed = client.flush(timeout=1.0)
        client.close()
        self.assertTrue(flushed)

    @patch("urllib.request.urlopen")
    def test_network_timeout_does_not_raise(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Connection timed out")

        client = LogMorph(
            api_key="lm_live_secret",
            flush_interval=0.05,
        )

        client.log("Timeout event")
        flushed = client.flush(timeout=1.0)
        client.close()
        self.assertTrue(flushed)


class TestLogMorphLoggingHandler(unittest.TestCase):
    """Test standard logging.Handler integration."""

    @patch("urllib.request.urlopen")
    def test_logging_handler_stream(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "accepted"}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        logger = logging.getLogger("test_logger_unique")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        handler = LogMorphHandler(
            api_key="lm_live_handler_test",
            source="logger-unit-test",
            flush_interval=0.05,
        )
        logger.addHandler(handler)

        logger.info("Informational message from standard logger")
        logger.warning("Warning message from standard logger")

        handler.flush()
        handler.close()

        self.assertTrue(mock_urlopen.called)


if __name__ == "__main__":
    unittest.main()
