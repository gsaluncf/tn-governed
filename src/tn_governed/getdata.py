"""Client for retained TN publications, fetched by the exact identity a selection pins."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import tn

from .publications import object_digest

_TN_MEDIA_TYPE = "application/vnd.tn+json"


@dataclass(frozen=True)
class GetDataConfig:
    """Immutable connection settings for the publication service."""

    base_url: str
    timeout_seconds: float = 5.0


@dataclass(frozen=True)
class FeedFetchFact:
    """Fetch metadata recorded without including data rows."""

    event_name: str
    feed_name: str
    request_path: str
    http_status: int
    content_type: str


@dataclass(frozen=True)
class FetchedFeed:
    """A selection's verified source publication and the metadata of its fetch."""

    publication: tn.GovernedObject
    fact: FeedFetchFact


class FeedFetchHTTPError(RuntimeError):
    """The service responded with a non-success HTTP status."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"feed fetch failed with HTTP {status}")


class FeedFetchResponseError(RuntimeError):
    """A successful HTTP response violated the publication representation contract."""


def fetch_governed_feed(config: GetDataConfig, selection: tn.DatasetSelection) -> FetchedFeed:
    """Fetch the exact source publication `selection` pins; it is parsed and verified once."""
    request_path = f"/v1/publications/{object_digest(selection.source_object_id)}"
    body, fact = _fetch(config, selection.dataset, request_path)
    try:
        publication = tn.GovernedObject.parse(body)
    except Exception as error:
        raise FeedFetchResponseError("publication is not an authenticated native TN object") from error
    if publication.id != selection.source_object_id:
        raise FeedFetchResponseError("publication identity differs from the accepted dataset selection")
    return FetchedFeed(publication=publication, fact=fact)


def _fetch(config: GetDataConfig, feed_name: str, request_path: str) -> tuple[bytes, FeedFetchFact]:
    request = Request(
        f"{config.base_url.rstrip('/')}{request_path}",
        headers={"Accept": _TN_MEDIA_TYPE},
        method="GET",
    )
    try:
        with urlopen(request, timeout=config.timeout_seconds) as response:
            content_type = response.headers.get("Content-Type", "")
            media_type = content_type.split(";", maxsplit=1)[0].strip().lower()
            if media_type != _TN_MEDIA_TYPE:
                raise FeedFetchResponseError(f"feed fetch returned unsupported media type {content_type!r}")
            body = response.read()
            if not body:
                raise FeedFetchResponseError("feed fetch returned an empty body")
            fact = FeedFetchFact(
                event_name="getdata.feed_fetched",
                feed_name=feed_name,
                request_path=request_path,
                http_status=response.status,
                content_type=content_type,
            )
            return body, fact
    except HTTPError as error:
        raise FeedFetchHTTPError(error.code) from error
    except URLError as error:
        raise FeedFetchHTTPError(0) from error
