# Security

## What canarykit touches

- **Sends** HTTP requests with synthetic data to the `[target]` you configure.
- **Runs** the `[fault]` and `command` source commands you write, through your shell (`shell=True`), with your permissions. That is deliberate: the commands are yours, and pipelines are the natural way to express them. It also means `canarykit.toml` is code. Review it, keep it out of version control (it's in `.gitignore`), and don't run configs you didn't write. canarykit never builds a command from data it reads or receives: `${VAR}` in a command is left for the shell to expand, so a value can't inject syntax, and nothing from a response or scanned store reaches a shell.
- **Reads** the files, command output and HTTP responses of the sources you list.
- **Writes** only to its own `runs/` directory.

It has no third-party dependencies, collects no telemetry and makes no network calls beyond the target and your sources. Python's standard `HTTP(S)_PROXY` variables are honoured, as with any urllib client.

## Secrets

- Read from environment variables with `${VAR}`; a missing variable is an error, never an empty string.
- Substituted only into `headers` and `url` values in memory. They're never written to `run.json`, `scan.json` or the report: hit locations and URLs are recorded as written in the config, before substitution.
- Headers are refused over plain `http://` unless the host is localhost (an SSH tunnel) or you set `allow_plaintext_http = true`.
- HTTP redirects are not followed, so an `Authorization` header can't be forwarded to a host you didn't name.
- Prefer tool-native credential stores in `command` sources (`~/.pgpass`, `PGSERVICE`, `REDISCLI_AUTH`, cloud CLI profiles) over passwords in arguments, which other local users can see in the process list.

## What it stores

- `run.json`: the synthetic customer, request metadata (status, timing, served-by fields) and a timeline. No response bodies.
- `scan.json`: for each hit, the source, file or URL, line and byte offset, and which pattern matched. Never the matching content. Errors are limited to messages canarykit wrote and OS error text; library messages that can quote what was read (a bad gzip header, for example) and command stderr are not stored.
- `report.md` and `summary.json`: built from the two files above. `--redact` also drops paths, URLs, internal hostnames and fault commands.
- "Served by" values from `record_fields` and `record_headers` are capped at 200 characters and only scalars are kept, so pointing one at a message body can't store it.
- All run files are created with mode 0600 in a 0700 directory. Responses are read up to 10 MiB and only checked for the canary, never stored.

## Reporting a vulnerability

Please open a private security advisory on this repository rather than a public issue.
