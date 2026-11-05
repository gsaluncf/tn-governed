import io
import json
import tarfile

from deployment.remote_model import input_bundle


def test_bundle_carries_endpoint_keys_and_metadata_without_source_database(tmp_path):
    endpoint = tmp_path / "native-model"
    reader = tmp_path / "sessions" / "reader"
    writer = tmp_path / "sessions" / "writer"
    for directory in (endpoint, reader, writer):
        directory.mkdir(parents=True)
    (reader / "tn.yaml").write_text("reader configuration")
    (reader / "key.bin").write_bytes(b"reader key")
    (writer / "tn.yaml").write_text("writer configuration")
    (endpoint / "native-metadata.json").write_text("encrypted metadata")
    (tmp_path / "market.sqlite").write_bytes(b"source plaintext")
    config = endpoint / "runtime.json"
    content = json.dumps({
        "governed_objects": {"native_reader_config_path": str(reader / "tn.yaml")},
        "output_tn_config_path": str(writer / "tn.yaml"),
    })
    config.write_text(content)
    payload, roots = input_bundle(config)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        names = archive.getnames()
        assert not any(name.endswith("market.sqlite") for name in names)
        assert any(name.endswith("reader/key.bin") for name in names)
        assert archive.extractfile(config.as_posix().lstrip("/")).read().decode() == content
    assert roots == [endpoint, reader, writer]


def test_bundle_rejects_session_paths_outside_the_trial(tmp_path):
    endpoint = tmp_path / "trial" / "native-model"
    endpoint.mkdir(parents=True)
    config = endpoint / "runtime.json"
    config.write_text(json.dumps({
        "governed_objects": {"native_reader_config_path": str(tmp_path / "account/tn.yaml")},
        "output_tn_config_path": str(endpoint.parent / "writer/tn.yaml"),
    }))
    import pytest

    with pytest.raises(ValueError, match="trial"):
        input_bundle(config)
