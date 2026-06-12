from kernel_hunter.analyzers.smatch import parse_smatch_output


def test_parse_smatch_null_deref() -> None:
    output = "drivers/foo/bar.c:42 warning: potentially dereferencing null pointer 'dev'\n"
    findings = parse_smatch_output(output)
    assert len(findings) == 1
    assert findings[0].category == "null_dereference"
    assert findings[0].confidence >= 80
    assert findings[0].file == "drivers/foo/bar.c"
