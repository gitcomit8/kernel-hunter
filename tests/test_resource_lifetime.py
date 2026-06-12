from kernel_hunter.analyzers.resource_lifetime import analyze_function, extract_functions


def test_resource_lifetime_missing_release() -> None:
    source = """
int demo(struct device *dev)
{
    struct clk *clk;
    clk = clk_get(dev, NULL);
    if (!clk)
        return -EINVAL;
    return 0;
}
"""
    functions = extract_functions(source)
    findings = analyze_function("drivers/foo/demo.c", functions[0])
    assert len(findings) == 1
    assert findings[0].category == "resource_lifetime"
    assert "clk_put" in findings[0].title


def test_resource_lifetime_balanced() -> None:
    source = """
int demo(struct device *dev)
{
    struct clk *clk;
    clk = clk_get(dev, NULL);
    clk_put(clk);
    return 0;
}
"""
    functions = extract_functions(source)
    findings = analyze_function("drivers/foo/demo.c", functions[0])
    assert findings == []
