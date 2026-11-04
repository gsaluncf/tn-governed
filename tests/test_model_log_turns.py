"""Model inference is read from every turn in the llama-server log, never only the first."""

from experiments.pvldb_evaluation.study_summary import log_turns

# Timing lines from a governed two-turn run: the decrypt call (task 0), then the report (task 164).
TWO_TURN_LOG = """\
0.05.597.906 I slot print_timing: id  0 | task 0 | prompt eval time =     857.10 ms /  3035 tokens (    0.28 ms per token,  3541.00 tokens per second)
0.05.597.940 I slot print_timing: id  0 | task 0 |        eval time =    1892.05 ms /   162 tokens (   11.75 ms per token,    85.09 tokens per second)
0.08.692.372 I slot print_timing: id  0 | task 164 | prompt eval time =    1699.40 ms /  5187 tokens (    0.33 ms per token,  3052.25 tokens per second)
0.08.692.399 I slot print_timing: id  0 | task 164 |        eval time =    1184.46 ms /    91 tokens (   13.16 ms per token,    75.98 tokens per second)
"""


def test_log_turns_sums_the_decrypt_and_report_turns():
    turns = log_turns(TWO_TURN_LOG)
    assert turns["inferences"] == 2
    assert turns["prompt_tokens"] == 3035 + 5187
    assert turns["decoded_tokens"] == 162 + 91
    assert abs(turns["prompt_seconds"] - (857.10 + 1699.40) / 1000) < 1e-9
    assert abs(turns["decode_seconds"] - (1892.05 + 1184.46) / 1000) < 1e-9


def test_log_turns_counts_no_inference_in_an_empty_log():
    assert log_turns("") == {"inferences": 0, "prompt_tokens": 0, "prompt_seconds": 0.0,
                             "decoded_tokens": 0, "decode_seconds": 0.0}
