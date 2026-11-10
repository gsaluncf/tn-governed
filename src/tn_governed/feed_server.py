"""Loopback HTTP server for retained TN publications, each served by its exact identity."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TextIO

_TN_CONTENT_TYPE = "application/vnd.tn+json; charset=utf-8"
_PUBLICATION_ROUTE = re.compile(r"/v1/publications/([0-9a-f]{64})")


@dataclass(frozen=True)
class FeedServerConfig:
    """The fetch event sink, the port, and the store publications are served from."""

    event_stream: TextIO
    port: int
    publication_store: object


class FeedRequestHandler(BaseHTTPRequestHandler):
    """The health route and one exact publication route; every other request is refused."""

    config: FeedServerConfig

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._write(HTTPStatus.OK, "application/json; charset=utf-8", b'{"ready":true}\n')
            return
        route = _PUBLICATION_ROUTE.fullmatch(self.path)
        if route is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._publication(f"sha256:{route[1]}")

    def do_POST(self) -> None:  # noqa: N802
        if _PUBLICATION_ROUTE.fullmatch(self.path) is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _publication(self, identity: str) -> None:
        """Serve one retained publication's exact bytes; a missing one is never regenerated."""
        try:
            body = self.config.publication_store.get(identity)
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        except ValueError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._write(HTTPStatus.OK, _TN_CONTENT_TYPE, body)
        _emit_event(self.config.event_stream, identity, self.path, _TN_CONTENT_TYPE)

    def _write(self, status: HTTPStatus, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def create_feed_server(config: FeedServerConfig) -> ThreadingHTTPServer:
    """Build a loopback server that serves `config`'s retained publications."""
    handler = type("BoundFeedRequestHandler", (FeedRequestHandler,), {"config": config})
    return ThreadingHTTPServer(("127.0.0.1", config.port), handler)


def _emit_event(event_stream: TextIO, feed_name: str, request_path: str, content_type: str) -> None:
    event_stream.write(
        json.dumps(
            {
                "event": "getdata.feed_served",
                "feed_name": feed_name,
                "request_path": request_path,
                "http_status": 200,
                "content_type": content_type,
            }
        )
        + "\n"
    )
    event_stream.flush()
