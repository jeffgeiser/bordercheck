# Security

## What canarykit touches

- **Sends** HTTP requests with synthetic data to the `[target]` you configure.
- **Runs** the `[fault]` and `command` source commands you write, through your shell, with your permissions. Treat `canarykit.toml` like code: review it, keep it out of version control (it's in `.gitignore`), and don't run configs you didn't write.
- **Reads** the files, command output and HTTP responses of the sources you list.
- **Writes** only to its own `runs/` directory.

It has no third-party dependencies, collects no telemetry and makes no network calls beyond the target and your sources.

## What it stores

- `run.json`: the synthetic customer, request metadata (status, timing, served-by fields) and a timeline. No response bodies.
- `scan.json`: for each hit, the source, file or URL, line and byte offset, and which pattern matched. Never the matching content.
- `report.md` and `summary.json`: built from the two files above.

## Reporting a vulnerability

Please open a private security advisory on this repository rather than a public issue.
