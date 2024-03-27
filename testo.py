import subprocess
import sys
import threading
import queue
import math
from os import get_terminal_size
from termcolor import colored, cprint
from time import sleep
import signal
import socket
import select

global debug

# Define a global list to hold all test case functions
test_cases = []


def testcase(func):
    def wrapper(tester, *args, **kwargs):
        passed = False

        title = f" ⏳ Starting test '{func.__name__}' "
        start_sep = "=" * math.floor((get_terminal_size().columns - len(title) - 1) / 2)
        end_sep = "=" * (
            get_terminal_size().columns - (len(start_sep) + len(title)) - 1
        )
        print(colored("\n" + start_sep + title + end_sep, "yellow"))
        try:
            func(tester, *args, **kwargs)
            print(colored(f"✅ Test '{func.__name__}': PASSED", "green"))
            passed = True
        except AssertionError as e:
            print(colored(f"❌ Test '{func.__name__}': FAILED - {e}", "red"))
        except Exception as e:
            print(colored(f"❌ Test '{func.__name__}': ERROR - {e}", "red"))
        print(colored(f"Test '{func.__name__}' finished", "yellow"))
        tester.teardown()  # Clean up after test

        return passed

    test_cases.append(wrapper)  # Register the test case
    return wrapper


class ExecutableTester:
    def __init__(self, executable_path):
        self.executable_path = executable_path
        self.process = None
        self.stdout_queue = queue.Queue()
        self.stderr_queue = queue.Queue()
        self.return_code = None
        self.server_socket = None
        self.connection_socket = None  # For TCP connections
        self.client_address = None  # For UDP responses

    def start_server(self, protocol, port):
        if protocol.lower() == "tcp":
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(("localhost", port))
            self.server_socket.listen(1)
            self.connection_socket, _ = self.server_socket.accept()
        elif protocol.lower() == "udp":
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind(("localhost", port))

    def stop_server(self):
        if self.connection_socket:
            self.connection_socket.close()
        if self.server_socket:
            self.server_socket.close()

    def send_message(self, message):
        if self.connection_socket:  # TCP
            self.connection_socket.sendall(message.encode())
        elif self.server_socket and self.client_address:  # UDP
            self.server_socket.sendto(message, self.client_address)

    def receive_message(self, timeout=5):
        if self.server_socket:
            self.server_socket.settimeout(timeout)
            try:
                if self.connection_socket:  # TCP
                    return self.connection_socket.recv(1024).decode()
                else:  # UDP
                    message, self.client_address = self.server_socket.recvfrom(1024)
                    return message
            except socket.timeout:
                return None

    def setup(self, args=["-t", "udp", "-s", "localhost", "-p", "4567"]):
        if self.process:
            self.teardown()
        self.process = subprocess.Popen(
            [self.executable_path] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
        )
        self._start_thread(self.read_stdout, self.stdout_queue)
        self._start_thread(self.read_stderr, self.stderr_queue)
        self.return_code = None

        sleep(0.2)  # Give some time for the process to start

    def _start_thread(self, target, queue):
        thread = threading.Thread(target=target, args=(queue,))
        thread.daemon = True  # Thread dies with the program
        thread.start()

    def read_stdout(self, queue):
        for line in iter(self.process.stdout.readline, ""):
            if debug:
                print(colored("STDOUT:", "blue"), colored(line, "blue"), end="")
            queue.put(line)

    def read_stderr(self, queue):
        for line in iter(self.process.stderr.readline, ""):
            if debug:
                print(colored("STDERR:", "magenta"), colored(line, "magenta"), end="")
            queue.put(line)

    def execute(self, input_data):
        self.process.stdin.write(input_data + "\n")
        self.process.stdin.flush()

        sleep(0.2)

    def get_stdout(self):
        output = []
        while not self.stdout_queue.empty():
            output.append(self.stdout_queue.get())
        return "".join(output)

    def get_stderr(self):
        output = []
        while not self.stderr_queue.empty():
            output.append(self.stderr_queue.get())
        return "".join(output)

    def teardown(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.return_code = self.process.returncode
            self.process = None

        self.stop_server()
        self.server_socket = None
        self.connection_socket = None

    def get_return_code(self):
        return self.return_code

    def send_signal(self, signal):
        self.process.send_signal(signal)

    def send_eof(self):
        self.process.stdin.close()


### TEST CASES ###


# PART 1 - Testing command-line aguments


@testcase
def no_args(tester):
    """Test that the program exits with a non-zero exit code when no arguments are provided"""
    tester.setup(args=[])
    assert tester.get_return_code() != 0, "Expected non-zero exit code."


@testcase
def no_type_arg(tester):
    """Test that the program exits with a non-zero exit code when the -t argument is not provided."""
    tester.setup(args=["-s", "localhost"])
    assert tester.get_return_code() != 0, "Expected non-zero exit code."


@testcase
def no_hostname(tester):
    """Test that the program exits with a non-zero exit code when the -s argument is not provided."""
    tester.setup(args=["-t", "udp"])
    assert tester.get_return_code() != 0, "Expected non-zero exit code."


@testcase
def all_args(tester):
    """Test that the program exits with a non-zero exit code when the -s argument is not provided."""
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])
    tester.send_eof()
    assert tester.get_return_code() == None, "Expected zero exit code."


# PART 2: UDP - Testing basic commands


@testcase
def udp_hello(tester):
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Invalid command for the START state
    tester.execute("Hello")

    stdout = tester.get_stdout()
    stderr = tester.get_stderr()
    assert "ERR:" in stderr, "Output does not match expected output."


@testcase
def udp_invalid_command(tester):
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Invalid command in general
    tester.execute("/pepe")

    stdout = tester.get_stdout()
    stderr = tester.get_stderr()
    assert "ERR:" in stderr, "Output does not match expected output."


@testcase
def udp_auth(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Check AUTH message received
    message = tester.receive_message()
    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected message."


@testcase
def udp_auth_port(tester):
    tester.start_server("udp", 1234)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "1234"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Check AUTH message received
    message = tester.receive_message()
    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected message."


@testcase
def udp_auth_nok(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()
    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected AUTH message."

    # Confirm the AUTH message
    tester.send_message(b"\x00\x00\x00")

    # Reply with NOK
    tester.send_message(b"\x01\x00\x00\x00\x00\x00nene\x00")

    sleep(0.2)

    # Check the output, should contain "Failure: nene"
    stderr = tester.get_stderr()
    assert any(
        ["Failure: nene" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Failure: nene' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x00"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_auth_nok_ok(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()
    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected AUTH message."

    # Confirm the AUTH message
    tester.send_message(b"\x00\x00\x00")

    # Reply with NOK
    tester.send_message(b"\x01\x00\x00\x00\x00\x00nene\x00")

    sleep(0.2)

    # Check the output, should contain "Failure: nene"
    stderr = tester.get_stderr()
    assert any(
        ["Failure: nene" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Failure: nene' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x00"
    ), "Incoming message does not match expected CONFIRM message."

    # Send a second AUTH message
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()
    assert (
        message == b"\x02\x00\x01a\x00c\x00b\x00"
    ), "Incoming message does not match expected AUTH message."

    # Confirm the AUTH message
    tester.send_message(b"\x00\x00\x01")

    # Reply with OK
    tester.send_message(b"\x01\x00\x01\x01\x00\x01yes\x00")

    sleep(0.2)

    # Check the output, should contain "Success: yes"
    stderr = tester.get_stderr()
    assert any(
        ["Success: yes" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Success: yes' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x01"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_auth_port_change(tester):
    # Start initial port listener
    tmp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp_socket.bind(("localhost", 1234))

    # Start normal port listener
    tester.start_server("udp", 4567)

    # Start client on temp port
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "1234"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server on tmp socket
    tmp_socket.settimeout(10)
    message, client_address = tmp_socket.recvfrom(1024)
    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected AUTH message."

    # Confirm the AUTH message on tmp socket
    tmp_socket.sendto(b"\x00\x00\x00", client_address)

    # Reply with NOK from different port (from now on the client should switch to it)
    tester.send_message(b"\x01\x00\x00\x01\x00\x00jojo\x00")

    sleep(0.2)

    # Check the output, should contain "Success: jojo"
    stderr = tester.get_stderr()
    assert any(
        ["Success: jojo" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Success: jojo' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x00"
    ), "Incoming message does not match expected CONFIRM message."


def auth_and_reply(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()

    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected AUTH message."

    # Confirm the AUTH message
    tester.send_message(b"\x00\x00\x00")

    # Reply with NOK
    tester.send_message(b"\x01\x00\x00\x01\x00\x00jojo\x00")

    sleep(0.2)

    # Check the output, should contain "Success: jojo"
    stderr = tester.get_stderr()
    assert any(
        ["Success: jojo" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Success: jojo' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x00"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_auth_ok(tester):
    auth_and_reply(tester)


@testcase
def udp_msg(tester):
    auth_and_reply(tester)

    tester.execute("ahojky")

    # Expect the message to be received by the server
    message = tester.receive_message()
    assert (
        message == b"\x04\x00\x01c\x00ahojky\x00"
    ), "Incoming message does not match expected MSG message."


@testcase
def udp_svr_msg(tester):
    auth_and_reply(tester)

    # Send a message from the server
    tester.send_message(b"\x04\x00\x01c\x00ahojky\x00")

    sleep(0.2)

    # Check the output, should contain "ahojky"
    stdout = tester.get_stdout()
    assert any(
        ["c: ahojky" in line for line in stdout.split("\n")]
    ), "Output does not match expected output."

    # Should receive CONFIRM for the MSG message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x01"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_bye1(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Send a message from the server
    tester.send_signal(signal.SIGINT)

    message = tester.receive_message()
    assert (
        message == b"\xff\x00\x00"
    ), "Incoming message does not match expected BYE message."


@testcase
def udp_bye2(tester):
    auth_and_reply(tester)

    # Send a message from the server
    tester.send_signal(signal.SIGINT)

    message = tester.receive_message()
    assert (
        message == b"\xff\x00\x01"
    ), "Incoming message does not match expected BYE message."


@testcase
def udp_server_err1(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Send a message from the server
    tester.send_message(b"\xfe\x00\x00server\x00chyba\x00")

    sleep(0.4)

    stderr = tester.get_stderr()
    assert any(
        ["ERR FROM server: chyba" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."

    # Should receive CONFIRM for the MSG message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x00"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_server_err2(tester):
    auth_and_reply(tester)

    # Send a message from the server
    tester.send_message(b"\xfe\x00\x01server\x00chyba\x00")

    sleep(0.2)

    # The ERR message should be printed out exactly like this
    stderr = tester.get_stderr()
    assert any(
        ["ERR FROM server: chyba" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."

    # Should receive CONFIRM for the ERROR message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x01"
    ), "Incoming message does not match expected CONFIRM message."

    # Should receive BYE for the ERROR message
    message = tester.receive_message()
    assert (
        message == b"\xff\x00\x01"
    ), "Incoming message does not match expected BYE message."


@testcase
def udp_join_ok(tester):
    auth_and_reply(tester)

    tester.execute("/rename user")

    tester.execute("/join channel")

    # Expect the join message to be received by the server
    message = tester.receive_message()

    assert (
        message == b"\x03\x00\x01channel\x00user\x00"
    ), "Incoming message does not match expected JOIN message."

    # Send REPLY message
    tester.send_message(b"\x01\x00\x01\x01\x00\x01jojo\x00")

    sleep(0.2)

    # Check the output, should contain "Success: jojo"
    stderr = tester.get_stderr()
    assert any(
        ["Success: jojo" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Success: jojo' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x01"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_join_nok(tester):
    auth_and_reply(tester)

    tester.execute("/rename user")

    tester.execute("/join channel")

    # Expect the join message to be received by the server
    message = tester.receive_message()

    assert (
        message == b"\x03\x00\x01channel\x00user\x00"
    ), "Incoming message does not match expected JOIN message."

    # Send REPLY message
    tester.send_message(b"\x01\x00\x01\x00\x00\x01jojo\x00")

    sleep(0.2)

    # Check the output, should contain "Failure: jojo"
    stderr = tester.get_stderr()
    assert any(
        ["Failure: jojo" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Failure: jojo' output."

    # Should receive CONFIRM for the REPLY message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x01"
    ), "Incoming message does not match expected CONFIRM message."


@testcase
def udp_multiple_auth(tester):
    auth_and_reply(tester)

    tester.execute("/auth d e f")

    sleep(0.2)

    # Client should not allow another auth and should output ERR
    stderr = tester.get_stderr()
    assert any(
        ["ERR: " in line for line in stderr.split("\n")]
    ), "Output does not match expected 'ERR: ' output."


@testcase
def udp_invalid_msg(tester):
    auth_and_reply(tester)

    # Send invalid message
    tester.send_message(b"\x06\x00\x01")

    sleep(0.2)

    # Check the output, should contain "ERR: "
    stderr = tester.get_stderr()
    assert any(
        ["ERR: " in line for line in stderr.split("\n")]
    ), "Output does not match expected 'ERR: ' output."

    # Should receive ERR for the invalid message
    message = tester.receive_message()
    assert (
        b"\xfe\x00\x01c\x00" in message
    ), "Incoming message does not match expected ERR message."


def udp_auth_err(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()
    assert (
        message == b"\x02\x00\x00a\x00c\x00b\x00"
    ), "Incoming message does not match expected AUTH message."

    # Confirm the AUTH message
    tester.send_message(b"\x00\x00\x00")

    # Send ERR message
    tester.send_message(b"\xfe\x00\x01server\x00ajaj\x00")

    sleep(0.2)

    # The client should output the ERR message exactly like this
    stderr = tester.get_stderr()
    assert any(
        ["ERR FROM server: ajaj" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."

    # The client should respond with BYE message
    message = tester.receive_message()
    assert (
        message == b"\xff\x00\x01"
    ), "Incoming message does not match expected BYE message."


### END TEST CASES ###


def run_tests(executable_path):
    test_cases_passed = 0
    tester = ExecutableTester(executable_path)
    for test in test_cases:
        test_cases_passed += 1 if test(tester) else 0

    cprint(
        f"\n{'✅' if test_cases_passed == len(test_cases) else '❌'} {test_cases_passed}/{len(test_cases)} test cases passed",
        "green" if test_cases_passed == len(test_cases) else "red",
    )


if __name__ == "__main__":
    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or (
        len(sys.argv) != 2 and len(sys.argv) != 3
    ):
        print("Usage: python test_executable.py <path_to_executable> [-d: debug]")
        sys.exit(1)
    executable_path = sys.argv[1]
    debug = len(sys.argv) == 3 and sys.argv[2] == "-d"
    run_tests(executable_path)
