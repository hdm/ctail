# ctail

Tail [Certificate Transparency](https://certificate.transparency.dev/) logs and extract hostnames.

This utility is an alternative to using hosted services like [crt.sh](https://crt.sh) or CertStream.

`ctail` is designed for quickly tailing the head of the logs and may not be the best choice for building comprehensive databases.

If you need something more comprehensive, consider the following open source alternatives:
* [certspotter](https://github.com/SSLMate/certspotter)
* [rxtls](https://github.com/x-stp/rxtls)


*Warning*: `ctail` can use a large amount of bandwidth (download) due to the rate of change in modern CT logs. If you are running this on a bandwidth-limited virtual machine, you may blow through your quota and rack up additional fees.

Usage:

```sh
$ go run github.com/hdm/ctail@latest -f -m '^autodiscover\.'
```

Logs are written to standard error and results are formatted as NDJSON/JSONL and written to standard output.

The output can be filtered using using tools like [jq](https://jqlang.org/).

Duplicate records are common and you might consider using a bloom filter in the pipeline.

![ctail feeding into jq](https://github.com/hdm/ctail/blob/main/docs/demo.gif?raw=true)
