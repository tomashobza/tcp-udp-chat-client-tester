import socket
import select
import subprocess
import logging
import threading
from sys import argv


class MessageType:
    CONFIRM = 0
    REPLY = 1
    AUTH = 2
    JOIN = 3
    MSG = 4
    ERR = 0xFE
    BYE = 0xFF


# Define ANSI escape sequences for colors
class AnsiColorCode:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


# Custom formatter that adds color to log messages based on their level
class ColorFormatter(logging.Formatter):
    COLOR_MAP = {
        logging.INFO: AnsiColorCode.BLUE,
        logging.ERROR: AnsiColorCode.RED,
        logging.WARNING: AnsiColorCode.YELLOW,
    }

    def format(self, record):
        color = self.COLOR_MAP.get(record.levelno, AnsiColorCode.RESET)
        message = super().format(record)
        return f"{color}{message}{AnsiColorCode.RESET}"


# Setup logging
logging.basicConfig(level=logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    ColorFormatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger("")
for handler in logger.handlers[:]:  # Remove all old handlers
    logger.removeHandler(handler)
logger.addHandler(console_handler)  # Add the custom handler


class UdpClientTester:
    def __init__(self, client_binary, server_host="localhost", server_port=4567):
        self.client_binary = client_binary
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((server_host, server_port))
        self.client_process = None

    def log_client_output(self, stream, stream_name):
        """Read and log output from a client process stream."""
        color_prefix = (
            AnsiColorCode.YELLOW if stream_name == "stdout" else AnsiColorCode.RED
        )
        for line in stream:
            logger.info(
                f"{color_prefix}Client {stream_name}: {line.strip()}{AnsiColorCode.RESET}"
            )

    def start_client(self, initial_input=None):
        if self.client_process:
            self.cleanup_client()
        self.client_process = subprocess.Popen(
            [self.client_binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
        )

        # Start threads to log stdout and stderr
        stdout_thread = threading.Thread(
            target=self.log_client_output,
            args=(self.client_process.stdout, "stdout"),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self.log_client_output,
            args=(self.client_process.stderr, "stderr"),
            daemon=True,
        )
        # stdout_thread.start()
        # stderr_thread.start()

        if initial_input:
            self.client_process.stdin.write(initial_input + "\n")
            self.client_process.stdin.flush()

    def cleanup_client(self):
        if self.client_process:
            self.client_process.terminate()
            self.client_process.wait()

    def send_input_to_client(self, message):
        self.client_process.stdin.write(message + "\n")
        self.client_process.stdin.flush()

    def receive_message(self, timeout=5):
        ready = select.select([self.server_socket], [], [], timeout)
        if ready[0]:
            data, addr = self.server_socket.recvfrom(1024)  # buffer size is 1024 bytes
            return data, addr
        else:
            return None, None

    def run_test(self, test_case, *args, **kwargs):
        self.start_client()  # Start a fresh client for each test
        try:
            logger.info(f"Starting test: {test_case.__name__}")
            success, message = test_case(self, *args, **kwargs)
            if success:
                logger.info(
                    f"{AnsiColorCode.GREEN}Test {test_case.__name__} PASSED: {message}{AnsiColorCode.RESET}"
                )
            else:
                logger.error(
                    f"{AnsiColorCode.RED}Test {test_case.__name__} FAILED: {message}{AnsiColorCode.RESET}"
                )
        except Exception as e:
            logger.error(f"Test {test_case.__name__} EXCEPTION: {e}")
        finally:
            self.cleanup_client()  # Ensure the client is cleaned up after each test

    def cleanup(self):
        self.server_socket.close()


# Example test cases
def test_send_and_receive(udp_tester):
    udp_tester.send_input_to_client("/auth testuser testpassword testdisplayname")
    data, addr = udp_tester.receive_message(timeout=10)
    has_corr_header = data[0] == MessageType.AUTH
    has_corr_id = int(data[2] << 8 | data[1]) == 0
    if has_corr_header and has_corr_id:
        return True, f"Received: {data}"
    else:
        return False, "Invalid response header or id" + f"Received: {data}"


def test_msg_without_auth(udp_tester):
    udp_tester.send_input_to_client("hello this is a message")
    data, addr = udp_tester.receive_message(timeout=10)
    has_corr_header = data[0] == MessageType.BYE
    has_corr_id = int(data[2] << 8 | data[1]) == 0
    if has_corr_header and has_corr_id:
        return True, f"Received: {data}"
    else:
        return False, "Invalid response header or id" + f"Received: {data}"


def main():
    if len(argv) < 2 or "--help" in argv[1]:
        print("Usage: python3 testing_server.py <path_to_client_binary>")
        return

    tester = UdpClientTester(argv[1])

    # Define test cases to run
    test_cases = [test_send_and_receive, test_msg_without_auth]

    # Run each test case
    for test in test_cases:
        tester.run_test(test)

    # Cleanup
    tester.cleanup()


if __name__ == "__main__":
    main()
