# ctail

Tail [Certificate Transparency](https://certificate.transparency.dev/) logs and extract hostnames.

This utility is an alternative to using hosted services like [crt.sh](https://crt.sh) or CertStream.

Usage:

```sh

$ go install github.com/hdm/ctail@latest
$ ctail -f -m '^autodiscover\.'
```

Logs are written to standard error and results are formatted as NDJSON/JSONL and written to standard output.

This makes it easy to pass ctail output into tools like [jq](https://jqlang.org/).

