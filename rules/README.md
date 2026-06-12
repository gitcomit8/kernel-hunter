# Rules

`resource_lifetime.toml` documents the initial acquire/release pairs used by
the first-slice analyzer. The Python analyzer currently embeds the same
conservative defaults so it can run without config plumbing; loading external
rule files is the next extension point.
