import io
from contextlib import contextmanager
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from threading import Thread

import pytest
from governed_edition_fixtures import signed_edition

from tn_governed.feed_server import FeedServerConfig, create_feed_server
from tn_governed.getdata import (
    FeedFetchHTTPError,
    FeedFetchResponseError,
    GetDataConfig,
    fetch_governed_feed,
)
from tn_governed.publications import PublicationStore


@contextmanager
def service(store):
    server = create_feed_server(FeedServerConfig(io.StringIO(), 0, store))
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield GetDataConfig(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        worker.join()
        server.server_close()


def test_pinned_selection_repeats_exact_bytes_after_server_and_store_restart(tmp_path):
    fixture = signed_edition(tmp_path / "edition")
    root = tmp_path / "publications"
    store = PublicationStore(root)
    store.put(fixture.source)
    with service(store) as config:
        first = fetch_governed_feed(config, fixture.selection)
        second = fetch_governed_feed(config, fixture.selection)
    with service(PublicationStore(root)) as config:
        restarted = fetch_governed_feed(config, fixture.selection)
    assert first.publication.forward() == second.publication.forward() == restarted.publication.forward()
    assert first.publication.forward() == fixture.source.forward()
    assert first.fact.request_path.endswith(fixture.source.id[7:])


def test_pinned_selection_missing_publication_fails_without_resealing(tmp_path):
    fixture = signed_edition(tmp_path / "edition")
    with (
        service(PublicationStore(tmp_path / "empty")) as config,
        pytest.raises(FeedFetchHTTPError) as failure,
    ):
        fetch_governed_feed(config, fixture.selection)
    assert failure.value.status == 404


def test_route_returning_another_valid_source_is_rejected_before_admission(tmp_path):
    first = signed_edition(tmp_path / "first")
    other = signed_edition(tmp_path / "other", session=first.session, edition="new")

    class WrongRoute:
        def get(self, identity):
            assert identity == first.source.id
            return other.source.forward()

    with (
        service(WrongRoute()) as config,
        pytest.raises(FeedFetchResponseError, match="identity"),
    ):
        fetch_governed_feed(config, first.selection)


def test_corrupt_publication_returns_no_business_body(tmp_path):
    fixture = signed_edition(tmp_path / "edition")
    store = PublicationStore(tmp_path / "publications")
    store.put(fixture.source)
    (store.root / "objects" / f"{fixture.source.id[7:]}.tn").write_bytes(b"substituted")
    with (
        service(store) as config,
        pytest.raises(FeedFetchHTTPError) as failure,
    ):
        fetch_governed_feed(config, fixture.selection)
    assert failure.value.status == 500


@pytest.mark.parametrize("path", [
    "/v1/publications/" + "0" * 63,
    "/v1/publications/%2e%2e/objects",
    "/v1/publications/" + "a" * 64 + "/extra",
    "/v1/feeds/portfolio.market.prices/data",
])
def test_unknown_or_encoded_traversal_route_returns_not_found(tmp_path, path):
    with service(PublicationStore(tmp_path / "publications")) as config:
        with pytest.raises(HTTPError) as failure:
            urlopen(config.base_url + path)
    assert failure.value.code == 404


def test_post_to_the_publication_route_is_not_allowed(tmp_path):
    with service(PublicationStore(tmp_path / "publications")) as config:
        request = Request(f"{config.base_url}/v1/publications/{'a' * 64}", data=b"", method="POST")
        with pytest.raises(HTTPError) as failure:
            urlopen(request)
    assert failure.value.code == 405
    assert failure.value.headers["Allow"] == "GET"
