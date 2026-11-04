import sys

import pytest

from experiments.pvldb_evaluation import publication_size


def test_editions_count_one_publication_per_column_and_batch():
    assert publication_size.editions(100000, 4096) == 50
    assert publication_size.editions(4096, 4096) == 2
    assert publication_size.editions(4097, 4096) == 4


def test_sizes_whose_result_would_exceed_the_binding_limit_are_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["publication_size", "--run-directory", str(tmp_path),
                                      "--rows", "100000", "--sizes", "64", "256"])
    with pytest.raises(SystemExit):
        publication_size.main()
    assert "[64]" in capsys.readouterr().err
    assert not any(tmp_path.iterdir())
