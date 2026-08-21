# Fuzzing seed corpus

One request per file, covering every documented challenge endpoint.
Suitable both as AFL++ seeds (`-i fuzz/corpus`) and libFuzzer seeds
(`./fuzz_dispatch fuzz/corpus/`).

The files use LF-only line endings; AFL++ / libFuzzer treat the bytes
verbatim, so the parser's `\r\n`/`\n` tolerance is what makes these
work. If your fuzzer normalizes newlines, add a preprocessing step.
