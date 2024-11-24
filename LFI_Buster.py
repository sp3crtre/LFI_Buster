import argparse
import requests
import time


class LFIScanner:
    def __init__(self, urls_file, payloads_file, cookie=None):
        # Initialize scanner with input files and optional cookie
        self.urls_file = urls_file
        self.payloads_file = payloads_file
        self.cookie = cookie
        self.urls = self._load_file(urls_file)
        self.payloads = self._load_file(payloads_file)

    def _load_file(self, file_path):
        """Helper method to load URLs or payloads from a file."""
        with open(file_path) as file:
            return file.read().splitlines()

    def _perform_request(self, url, payload):
        url_with_payload = f"{url}{payload}"
        start_time = time.time()

        try:
            response = requests.get(url_with_payload, cookies={'cookie': self.cookie} if self.cookie else None)
            response.raise_for_status()  # Check for HTTP errors
        except requests.exceptions.RequestException as e:
            return False, url_with_payload, time.time() - start_time, str(e), None

        # Check if the response indicates LFI (based on certain content, like passwd file)
        if "root:x" in response.text or "www-data" in response.text:
            return True, url_with_payload, time.time() - start_time, None, "Potential LFI vulnerability detected"
        return True, url_with_payload, time.time() - start_time, None, None

    def scan(self):
        """Scan all URLs with each payload and print the results."""
        for url in self.urls:
            for payload in self.payloads:
                success, url_with_payload, response_time, error_message, lfi_warning = self._perform_request(url, payload)

                # Display the result based on success and response time
                if success and response_time <= 20:
                    if lfi_warning:
                        print(f"\033[1;33m[INFO] LFI Detected: {url_with_payload} - {response_time:.2f} seconds - {lfi_warning}\033[0m")
                    else:
                        print(f"\033[1;32m[SAFE] No LFI Detected: {url_with_payload} - {response_time:.2f} seconds\033[0m")
                else:
                    print(f"\033[1;31m[ERROR] URL: {url_with_payload} - {response_time:.2f} seconds - Error: {error_message}\033[0m")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Scan URLs for Local File Inclusion (LFI) vulnerabilities.")
    parser.add_argument("-u", "--urls", required=True, help="File containing the list of URLs to scan.")
    parser.add_argument("-d", "--data", required=True, help="File containing the list of LFI payloads to test.")
    parser.add_argument("-c", "--cookie", help="Optional cookie to include in the GET requests.")
    args = parser.parse_args()

    # Initialize and run the LFI scanner
    lfi_scanner = LFIScanner(args.urls, args.data, args.cookie)
    lfi_scanner.scan()


if __name__ == "__main__":
    main()
