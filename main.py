import argparse
import requests
import logging
import sys
import json
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Metadata path shapes appended to the operator named target, and nothing else.
# This tool never contacts a fixed metadata address on its own: every request
# goes to the base URL the operator passes on the command line.
METADATA_PATHS = {
    "AWS": "/latest/meta-data/",
    "Azure": "/metadata/instance?api-version=2020-09-01",
    "GCP": "/computeMetadata/v1/"
}

MASK = "***"


def describe_metadata(cloud_provider, metadata, show_values):
    """
    Builds the report entry for one provider.

    By default values are masked: the report names the keys or fields that
    came back and their shape, never the values themselves, because metadata
    values are often credentials or instance secrets. Full values appear
    only when the operator passes --show-values.
    """
    if show_values:
        return {"values_shown": True, "data": metadata}
    report = {"values_masked": True}
    if isinstance(metadata, dict):
        # Only the top level keys are named. A nested dict shows up as the
        # type name dict, so its inner keys stay out of the masked report.
        report["fields"] = {
            key: {"type": type(value).__name__, "value": MASK}
            for key, value in metadata.items()
        }
    elif isinstance(metadata, str):
        lines = [line for line in metadata.splitlines() if line.strip()]
        report["line_count"] = len(lines)
        report["character_count"] = len(metadata)
        report["values"] = MASK
    else:
        report["type"] = type(metadata).__name__
        report["values"] = MASK
    return report


class MetadataScanner:
    """
    A class to scan an operator named target for cloud metadata endpoints.
    """

    def __init__(self, target, timeout=5, user_agent="vuln-Cloud-Metadata-Scanner/1.0", show_values=False):
        """
        Initializes the MetadataScanner.

        Args:
            target (str): Base URL named by the operator. The AWS, Azure, and
                GCP metadata paths are built onto this target only.
            timeout (int): Timeout in seconds for HTTP requests.
            user_agent (str): User agent string sent on every request.
            show_values (bool): Include full metadata values in the report.
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent
        self.show_values = show_values
        # Plain string joining, not urljoin. If the operator names a target
        # with a path prefix, the metadata path lands after that prefix,
        # which is what I want when the target is a proxy mounted under one.
        self.metadata_endpoints = {
            provider: self.target + path
            for provider, path in METADATA_PATHS.items()
        }

    def scan_endpoint(self, cloud_provider, headers=None):
        """
        Scans a specific cloud metadata endpoint on the named target.

        Returns:
            tuple: (True, report) if the endpoint answered, (False, error) otherwise.
        """
        try:
            url = self.metadata_endpoints[cloud_provider]
            request_headers = {"User-Agent": self.user_agent}
            if cloud_provider == "GCP":
                request_headers["Metadata-Flavor"] = "Google"
            elif cloud_provider == "Azure":
                request_headers["Metadata"] = "true"
            if headers:
                # Caller headers are applied last, so a caller can replace
                # even the provider header above. Nothing in main passes any
                # today, but scan_endpoint is public and I keep that order.
                request_headers.update(headers)

            logging.info(f"Attempting to access {cloud_provider} metadata endpoint: {url}")

            response = requests.get(url, timeout=self.timeout, headers=request_headers, allow_redirects=False)
            # Redirects are not followed and raise_for_status turns a 3xx
            # into a failure as well, since HTTPError is a RequestException.
            # A metadata path that only redirects has not answered here.
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            if cloud_provider == "Azure":
                try:
                    metadata = response.json()
                except ValueError:
                    # The endpoint answered with HTTP 200 but the body is
                    # not JSON. That still counts as answered, so fall back
                    # to the text shape used for the other providers
                    # instead of reporting the endpoint as silent.
                    logging.info("Azure endpoint answered with a non-JSON body; reporting it as text.")
                    metadata = response.text
            else:
                metadata = response.text

            logging.info(f"Successfully accessed {cloud_provider} metadata.")
            return True, describe_metadata(cloud_provider, metadata, self.show_values)

        except json.JSONDecodeError as e:
            # requests raises its JSONDecodeError (a subclass of this) from
            # response.json(); it must be caught before RequestException,
            # which it also subclasses, or this branch can never run.
            error_message = f"Error decoding JSON response from {cloud_provider}: {e}"
            logging.error(error_message)
            return False, error_message
        except requests.exceptions.RequestException as e:
            error_message = f"Error accessing {cloud_provider} metadata: {e}"
            logging.error(error_message)
            return False, error_message
        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            logging.error(error_message)
            return False, error_message

    def scan_all_endpoints(self):
        """
        Scans all configured cloud metadata endpoints on the named target.

        Returns:
            dict: A dictionary containing the results of scanning each endpoint.
        """
        results = {}
        for provider, url in self.metadata_endpoints.items():
            success, data = self.scan_endpoint(provider)
            results[provider] = {"success": success, "data": data}
        return results


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Checks whether an operator named target exposes cloud metadata paths (AWS, Azure, GCP shapes). Only the target named on the command line is contacted.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "target",
        help="Base URL of the target to test, for example http://127.0.0.1:8080. The AWS path /latest/meta-data/, the Azure path /metadata/instance, and the GCP path /computeMetadata/v1/ are built onto this URL only."
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for HTTP requests. Default is 5 seconds."
    )

    parser.add_argument(
        "-u",
        "--user-agent",
        type=str,
        default="vuln-Cloud-Metadata-Scanner/1.0",
        help="Custom user agent string, sent on every request."
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file to save the scan results (JSON format)."
    )

    parser.add_argument(
        "--providers",
        nargs="+",
        choices=["AWS", "Azure", "GCP"],
        help="Specify which cloud providers to scan (AWS, Azure, GCP). If not specified, all providers will be scanned."
    )

    parser.add_argument(
        "--show-values",
        action="store_true",
        help="Include full metadata values in the output. By default values are masked and only key names and shapes are reported."
    )


    return parser


def main():
    """
    Main function to execute the cloud metadata scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input Validation
    if args.timeout <= 0:
        print("Error: Timeout value must be greater than 0.")
        sys.exit(1)

    parsed = urlparse(args.target)
    if not all([parsed.scheme, parsed.netloc]):
        print("Error: target must be a full URL, for example http://127.0.0.1:8080")
        sys.exit(1)

    scanner = MetadataScanner(target=args.target, timeout=args.timeout, user_agent=args.user_agent, show_values=args.show_values)

    if args.providers:
        results = {}
        for provider in args.providers:
            success, data = scanner.scan_endpoint(provider)
            results[provider] = {"success": success, "data": data}
    else:
        results = scanner.scan_all_endpoints()

    if not any(entry["success"] for entry in results.values()):
        print("Scan did not complete: no provider endpoint on the named target answered. No results verdict is reported.", file=sys.stderr)
        sys.exit(1)

    # Output results
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            print(f"Scan results saved to {args.output}")
        except Exception as e:
            print(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Test a named target against all provider path shapes:
#    python main.py http://127.0.0.1:8080
#
# 2. Run with a custom timeout of 10 seconds:
#    python main.py http://127.0.0.1:8080 -t 10
#
# 3. Run with a custom user agent (sent on every request):
#    python main.py http://127.0.0.1:8080 -u "MyCustomScanner/1.0"
#
# 4. Save the (masked by default) results to a JSON file:
#    python main.py http://127.0.0.1:8080 -o results.json
#
# 5. Test specific providers only (e.g., AWS and Azure):
#    python main.py http://127.0.0.1:8080 --providers AWS Azure
