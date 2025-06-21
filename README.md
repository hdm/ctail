# ctail

Tail [Certificate Transparency](https://certificate.transparency.dev/) logs and extract hostnames.

This utility is an alternative to using hosted services like [crt.sh](https://crt.sh) or CertStream.

Usage:

```sh
$ go run github.com/hdm/ctail@latest -f -m '^autodiscover\.'
```

Logs are written to standard error and results are formatted as NDJSON/JSONL and written to standard output.

The output can be filtered using using tools like [jq](https://jqlang.org/).

Duplicate records are common and you might consider using a bloom filter in the pipeline.
