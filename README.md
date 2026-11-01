# vuln-Cloud-Metadata-Scanner

I built this to test one named target at a time: does the base URL you give it answer on the cloud metadata path shapes? It builds three paths onto your target and nothing else:

- AWS shape: `/latest/meta-data/`
- Azure shape: `/metadata/instance?api-version=2020-09-01`
- GCP shape: `/computeMetadata/v1/`

It only ever contacts the target you name on the command line. There is no default target and no run without one, and it never queries a cloud metadata address on its own. Point it at your own host or at an application you are testing for SSRF reachability, and the requests go to that address only.

Returned metadata is reported by key name and shape with the values masked by default, in stdout and in the `--output` file, because metadata values are often credentials or instance details you do not want sitting in a report. Pass `--show-values` only when you actually need the full values in the output.

If no provider endpoint on the named target answers, the run exits non-zero and prints no results verdict.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-cloud-metadata-scanner`

## Usage
`python main.py <target-base-url> [params]`

Example: `python main.py http://127.0.0.1:8080 --providers AWS Azure`

## Parameters
- `target`: Base URL to test (required, positional).
- `-h`: Show help message and exit
- `-t`: Timeout in seconds for HTTP requests. Default is 5 seconds.
- `-u`: Custom user agent string, sent on every request.
- `-o`: Output file to save the scan results (JSON format).
- `--providers`: Which providers to test (AWS, Azure, GCP). Default is all three.
- `--show-values`: Include full metadata values instead of the masked report.

## License
Copyright (c) ShadowGuard-AI
