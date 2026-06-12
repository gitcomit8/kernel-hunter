from kernel_hunter.analyzers.history import classify_commit_message, is_interesting_added_line


def test_classify_fix_commit() -> None:
    assert classify_commit_message("net: fix NULL pointer dereference") == "null_dereference"
    assert classify_commit_message("driver: refactor comments") is None


def test_interesting_added_line() -> None:
    assert is_interesting_added_line("if (!foo)")
    assert is_interesting_added_line("goto err_put_clk;")
    assert not is_interesting_added_line("int ret = 0;")
