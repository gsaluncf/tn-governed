"""Thin application adapter for the governed tn-llama client."""

from __future__ import annotations

from pathlib import Path

import tn
from tn_llama_client.clients import GovernedLlamaClient
from tn_llama_client.protocol import build_model_request, model_request_digest
from tn_llama_client.transcript import HttpTranscript

_LLAMA_SOURCE_REVISION = "3f545beccee69d9975f466ec7e45fd9aacd8ba90"


def submit_governed_report(
    object: tn.GovernedObject, *, prompt: str, use: tn.UseContext, destination: str,
    base_url: str, api_key: str, transcript_path: Path, output_reader, publication_store,
    bind_request: bool = False,
):
    """Send the publication and admit its report, optionally requiring request evidence.

    bind_request requires a signed tool completion carrying the submitted request
    digest. Workflows without tool calls leave this option disabled.
    """
    client = GovernedLlamaClient(base_url, api_key, HttpTranscript(transcript_path))
    if bind_request:
        body = build_model_request(object, prompt, use, destination=destination)
        expected_digest = model_request_digest(body)
        release = client.submit_request(body)
        report = output_reader.open(release, expected_request_digest=expected_digest)
    else:
        release = client.submit_model(object, prompt, use, destination=destination)
        report = output_reader.open(release)
    for tool in getattr(release, "tool_objects", ()):
        publication_store.put(tool)
    publication_store.put(release.output_object)
    return release, report
