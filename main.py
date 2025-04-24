import argparse
import requests
import logging
import sys
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MetadataScanner:
    """
    A class to scan for cloud metadata endpoints and retrieve information.
    """

    def __init__(self, timeout=5, user_agent="vuln-Cloud-Metadata-Scanner/1.0"):
        """
        Initializes the MetadataScanner with a timeout and user agent.

        Args:
            timeout (int): Timeout in seconds for HTTP requests.
            user_agent (str): User agent string for HTTP requests.
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self.metadata_endpoints = {
            "AWS": "http://169.254.169.254/latest/meta-data/",
            "Azure": "http://169.254.169.254/metadata/instance?api-version=2020-09-01",
            "GCP": "http://metadata.google.internal/computeMetadata/v1/"
        }

    def scan_endpoint(self, cloud_provider, headers=None):
        """
        Scans a specific cloud metadata endpoint.

        Args:
            cloud_provider (str): The cloud provider (e.g., "AWS", "Azure", "GCP").
            headers (dict): Optional headers to include in the request.

        Returns:
            tuple: (True, metadata) if successful, (False, error_message) otherwise.
        """
        try:
            url = self.metadata_endpoints[cloud_provider]
            if cloud_provider == "GCP":
                if headers is None:
                    headers = {"Metadata-Flavor": "Google"}
            elif cloud_provider == "Azure":
               if headers is None:
                    headers = {"Metadata": "true"}
            
            logging.info(f"Attempting to access {cloud_provider} metadata endpoint: {url}")

            response = requests.get(url, timeout=self.timeout, headers=headers, allow_redirects=False)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            if cloud_provider == "Azure":
                 metadata = response.json()
            else:
                metadata = response.text

            logging.info(f"Successfully accessed {cloud_provider} metadata.")
            return True, metadata

        except requests.exceptions.RequestException as e:
            error_message = f"Error accessing {cloud_provider} metadata: {e}"
            logging.error(error_message)
            return False, error_message
        except json.JSONDecodeError as e:
            error_message = f"Error decoding JSON response from {cloud_provider}: {e}"
            logging.error(error_message)
            return False, error_message
        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            logging.error(error_message)
            return False, error_message

    def scan_all_endpoints(self):
        """
        Scans all configured cloud metadata endpoints.

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
        description="Identifies potential exposure of cloud metadata endpoints.",
        formatter_class=argparse.RawTextHelpFormatter
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
        help="Custom user agent string for HTTP requests."
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

    scanner = MetadataScanner(timeout=args.timeout, user_agent=args.user_agent)

    if args.providers:
        results = {}
        for provider in args.providers:
            success, data = scanner.scan_endpoint(provider)
            results[provider] = {"success": success, "data": data}
    else:
        results = scanner.scan_all_endpoints()

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
# 1. Run the scanner against all cloud providers with default settings:
#    python main.py
#
# 2. Run the scanner with a custom timeout of 10 seconds:
#    python main.py -t 10
#
# 3. Run the scanner with a custom user agent:
#    python main.py -u "MyCustomScanner/1.0"
#
# 4. Run the scanner and save the output to a JSON file:
#    python main.py -o results.json
#
# 5. Run the scanner against specific cloud providers (e.g., AWS and Azure):
#    python main.py --providers AWS Azure
#
# 6. Run the scanner against a specific cloud providers and save results to file.
#    python main.py --providers AWS -o aws_results.json