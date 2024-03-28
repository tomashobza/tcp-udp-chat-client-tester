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
global run_tcp
global run_udp
global test

# Define a global list to hold all test case functions
udp_test_cases = []
tcp_test_cases = []


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

    # pass in the testcase name
    wrapper_func = wrapper
    wrapper_func.__name__ = func.__name__

    # Register the test case
    if "udp" in func.__name__:
        udp_test_cases.append(wrapper_func)
    elif "tcp" in func.__name__:
        tcp_test_cases.append(wrapper_func)
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
            # Start a new thread to run the blocking accept call
            thread = threading.Thread(target=self.accept_connection)
            thread.daemon = True  # Daemon threads exit when the main program does
            thread.start()

        elif protocol.lower() == "udp":
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind(("localhost", port))

    def accept_connection(self):
        self.connection_socket, _ = self.server_socket.accept()

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
        self.stdout_queue = queue.Queue()
        self.stderr_queue = queue.Queue()
        self.process = subprocess.Popen(
            [self.executable_path] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,  # Line buffered
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


# PART 2: UDP


@testcase
def udp_hello(tester):
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    # Invalid command for the START state
    tester.execute("Hello")

    stdout = tester.get_stdout()
    stderr = tester.get_stderr()
    assert "ERR:" in stderr, "Output does not match expected output."


@testcase
def udp_not_auth(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])
    tester.execute("/join")

    # The ERR message should be printed out exactly like this
    stderr = tester.get_stderr()
    assert any(
        ["ERR:" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


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

    # Reply with OK from different port (from now on the client should switch to it)
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


# Helper function
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

    # Reply with OK
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
    tester.send_message(b"\x04\x00\x01smrt\x00ahojky\x00")

    sleep(0.2)

    # Check the output, should contain "ahojky"
    stdout = tester.get_stdout()
    assert any(
        ["smrt: ahojky" in line for line in stdout.split("\n")]
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
def udp_bye3(tester):
    auth_and_reply(tester)

    # Send a message from the server
    tester.process.stdin.close()

    message = tester.receive_message()
    assert (
        message == b"\xff\x00\x01"
    ), "Incoming message does not match expected BYE message."


@testcase
def udp_server_err1(tester):
    tester.start_server("udp", 4567)
    tester.setup(args=["-t", "udp", "-s", "localhost", "-p", "4567"])

    tester.execute("/auth a b c")

    sleep(0.2)

    # Send CONFIRM message
    tester.send_message(b"\x00\x00\x00")

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

    # Send CONFIRM message
    tester.send_message(b"\x00\x00\x01")

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


@testcase
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

    # Check confirm of the ERR message
    message = tester.receive_message()
    assert (
        message == b"\x00\x00\x01"
    ), "Incoming message does not match expected CONFIRM message."

    # The client should respond with BYE message
    message = tester.receive_message()
    assert (
        message == b"\xff\x00\x01"
    ), "Incoming message does not match expected BYE message."


# PART 3: TCP


@testcase
def tcp_hello(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])

    # Invalid command for the START state
    tester.execute("Hello")

    stdout = tester.get_stdout()
    stderr = tester.get_stderr()
    assert "ERR:" in stderr, "Output does not match expected output."


@testcase
def tcp_not_auth(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])
    tester.execute("/join")

    # The ERR message should be printed out exactly like this
    stderr = tester.get_stderr()
    assert any(
        ["ERR:" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


@testcase
def tcp_invalid_command(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])

    # Invalid command in general
    tester.execute("/pepe")

    stdout = tester.get_stdout()
    stderr = tester.get_stderr()
    assert "ERR:" in stderr, "Output does not match expected output."


@testcase
def tcp_auth(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])
    tester.execute("/auth a b c")

    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected AUTH message."


@testcase
def tcp_auth_ok(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])
    tester.execute("/auth a b c")

    # Check AUTH message received
    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected AUTH message."

    # Send REPLY message
    tester.send_message("REPLY OK IS vsechno cajk\r\n")

    sleep(0.2)

    # Check the output, should contain "Success: vsechno cajk"
    stderr = tester.get_stderr()
    assert any(
        ["Success: vsechno cajk" == line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


@testcase
def tcp_auth_nok(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])
    tester.execute("/auth a b c")

    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected AUTH message."

    tester.send_message("REPLY NOK IS nic cajk\r\n")

    sleep(0.2)

    stderr = tester.get_stderr()
    assert any(
        ["Failure: nic cajk" == line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


@testcase
def tcp_auth_port(tester):
    tester.start_server("tcp", 1234)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "1234"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Check AUTH message received
    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected message."


@testcase
def tcp_auth_nok_ok(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])
    tester.execute("/auth a b c")

    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected AUTH message."

    tester.send_message("REPLY NOK IS nic cajk\r\n")

    sleep(0.2)

    stderr = tester.get_stderr()
    assert any(
        ["Failure: nic cajk" == line for line in stderr.split("\n")]
    ), "Output does not match expected error message."

    tester.execute("/auth d e f")

    message = tester.receive_message()
    assert (
        message == "AUTH d AS f USING e\r\n"
    ), "Incoming message does not match expected AUTH message."

    tester.send_message("REPLY OK IS vsechno cajk\r\n")

    sleep(0.2)

    stderr = tester.get_stderr()
    assert any(
        ["Success: vsechno cajk" == line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


# Helper function
def tcp_auth_and_reply(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])

    # Send AUTH command
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected AUTH message."

    # Send REPLY message
    tester.send_message("REPLY OK IS vsechno cajk\r\n")

    sleep(0.2)

    # Check the output, should contain "Success: vsechno cajk"
    stderr = tester.get_stderr()
    assert any(
        ["Success: vsechno cajk" == line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


@testcase
def tcp_auth_ok(tester):
    tcp_auth_and_reply(tester)


@testcase
def tcp_msg(tester):
    tcp_auth_and_reply(tester)

    tester.execute("ahojky")

    # Expect the message to be received by the server
    message = tester.receive_message()
    assert (
        message == "MSG FROM c IS ahojky\r\n"
    ), "Incoming message does not match expected MSG message."


@testcase
def tcp_svr_msg(tester):
    tcp_auth_and_reply(tester)

    # Send a message from the server
    tester.send_message("MSG FROM SeverusSnape IS ahojky\r\n")

    sleep(0.2)

    # Check the output, should contain "ahojky"
    stdout = tester.get_stdout()
    assert any(
        ["SeverusSnape: ahojky" in line for line in stdout.split("\n")]
    ), "Output does not match expected output."


@testcase
def tcp_bye1(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])

    sleep(0.2)

    # Send a message from the server
    tester.send_signal(signal.SIGINT)

    message = tester.receive_message()
    assert message == "BYE\r\n", "Incoming message does not match expected BYE message."


@testcase
def tcp_bye2(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])

    sleep(0.2)

    # Send a message from the server
    tester.process.stdin.close()

    message = tester.receive_message()
    assert message == "BYE\r\n", "Incoming message does not match expected BYE message."


@testcase
def tcp_bye3(tester):
    tcp_auth_and_reply(tester)

    # Send a message from the server
    tester.process.stdin.close()

    message = tester.receive_message()
    assert message == "BYE\r\n", "Incoming message does not match expected BYE message."


@testcase
def tcp_server_err1(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])

    # Send a message from the server
    tester.send_message("ERR FROM jetovp IS rdeli\r\n")

    sleep(0.4)

    stderr = tester.get_stderr()
    assert any(
        ["ERR FROM jetovp: rdeli" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


@testcase
def tcp_server_err2(tester):
    tcp_auth_and_reply(tester)

    # Send a message from the server
    tester.send_message("ERR FROM chuj IS bobr\r\n")

    sleep(0.4)

    stderr = tester.get_stderr()
    assert any(
        ["ERR FROM chuj: bobr" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."


@testcase
def tcp_join_ok(tester):
    tcp_auth_and_reply(tester)

    tester.execute("/rename user")

    tester.execute("/join channel")

    # Expect the join message to be received by the server
    message = tester.receive_message()
    assert (
        message == "JOIN channel AS user\r\n"
    ), "Incoming message does not match expected JOIN message."

    # Send REPLY message
    tester.send_message("REPLY OK IS takjo brasko ale bud hodnej\r\n")

    sleep(0.2)

    # Check the output, should contain "Success: jojo"
    stderr = tester.get_stderr()
    assert any(
        ["Success: takjo brasko ale bud hodnej" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Success: jojo' output."


@testcase
def tcp_join_nok(tester):
    tcp_auth_and_reply(tester)

    tester.execute("/rename user")

    tester.execute("/join channel")

    # Expect the join message to be received by the server
    message = tester.receive_message()
    assert (
        message == "JOIN channel AS user\r\n"
    ), "Incoming message does not match expected JOIN message."

    # Send REPLY message
    tester.send_message("REPLY NOK IS minus boiiii\r\n")

    sleep(0.2)

    # Check the output, should contain "Success: jojo"
    stderr = tester.get_stderr()
    assert any(
        ["Failure: minus boiiii" in line for line in stderr.split("\n")]
    ), "Output does not match expected 'Success: jojo' output."


@testcase
def tcp_multiple_auth(tester):
    tcp_auth_and_reply(tester)

    tester.execute("/auth d e f")

    sleep(0.2)

    # Client should not allow another auth and should output ERR
    stderr = tester.get_stderr()
    assert any(
        ["ERR: " in line for line in stderr.split("\n")]
    ), "Output does not match expected 'ERR: ' output."


@testcase
def tcp_invalid_msg(tester):
    tcp_auth_and_reply(tester)

    # Send invalid message
    tester.send_message("TVOJE MAMINKA\r\n")

    sleep(0.2)

    # Check the output, should contain "ERR: "
    stderr = tester.get_stderr()
    assert any(
        ["ERR: " in line for line in stderr.split("\n")]
    ), "Output does not match expected 'ERR: ' output."


@testcase
def tcp_auth_err(tester):
    tester.start_server("tcp", 4567)
    tester.setup(args=["-t", "tcp", "-s", "localhost", "-p", "4567"])
    tester.execute("/auth a b c")

    # Expect the auth message to be received by the server
    message = tester.receive_message()
    assert (
        message == "AUTH a AS c USING b\r\n"
    ), "Incoming message does not match expected AUTH message."

    # Send ERR message
    tester.send_message("ERR FROM server IS ajaj\r\n")

    sleep(0.2)

    # The client should output the ERR message exactly like this
    stderr = tester.get_stderr()
    assert any(
        ["ERR FROM server: ajaj" in line for line in stderr.split("\n")]
    ), "Output does not match expected error message."

    # The client should respond with BYE message
    message = tester.receive_message()
    assert message == "BYE\r\n", "Incoming message does not match expected BYE message."


### END TEST CASES ###


def run_tests(executable_path, udp=False, tcp=False, test_case=None):
    test_cases_passed = 0
    tester = ExecutableTester(executable_path)

    total_cases = 0

    if test_case is None:
        # Test UDP
        if udp:
            total_cases += len(udp_test_cases)
            for test in udp_test_cases:
                test_cases_passed += 1 if test(tester) else 0

        # Test TCP
        if tcp:
            total_cases += len(tcp_test_cases)
            for test in tcp_test_cases:
                test_cases_passed += 1 if test(tester) else 0
    else:
        test_found = False

        # Find and run the specified UDP test case
        if udp:
            for udp_test in udp_test_cases:
                if udp_test.__name__ == test_case:
                    total_cases += 1
                    test_cases_passed += 1 if udp_test(tester) else 0
                    test_found = True
                    break

        # Find and run the specified TCP test case if it wasn't found in UDP
        if tcp and not test_found:
            for tcp_test in tcp_test_cases:
                if tcp_test.__name__ == test_case:
                    total_cases += 1
                    test_cases_passed += 1 if tcp_test(tester) else 0
                    test_found = True
                    break

        if not test_found:
            print(
                f"Error: Test case '{test_case}' not found in the specified protocol tests."
            )
            return

    cprint(
        f"\n{'✅' if test_cases_passed == total_cases else '❌'} {test_cases_passed}/{total_cases} test cases passed",
        "green" if test_cases_passed == total_cases else "red",
    )


if __name__ == "__main__":
    # Default settings
    debug = False
    udp = True
    tcp = True
    test_case = None

    executable_path = None

    if "-h" in sys.argv:
        print(
            "Usage: python test_executable.py <path_to_executable> [-d: debug] [-t <testcase_name>] [-p <udp|tcp>]"
        )
        sys.exit(0)

    args = iter(sys.argv[1:])  # Skip the script name
    for arg in args:
        if arg == "-d":
            debug = True
        elif arg == "-t":
            try:
                test_case = next(args)  # Get the next argument as the test case name
                if test_case not in [
                    tc.__name__ for tc in udp_test_cases
                ] and test_case not in [tc.__name__ for tc in tcp_test_cases]:
                    print(f"Error: Test case '{test_case}' not recognized.")
                    sys.exit(1)
            except StopIteration:
                print("Error: -t requires a test case name.")
                sys.exit(1)
        elif arg == "-p":
            try:
                protocol = next(args).lower()  # Get the next argument as the protocol
                if protocol == "udp":
                    tcp = False
                elif protocol == "tcp":
                    udp = False
                else:
                    print("Error: Protocol must be either 'udp' or 'tcp'.")
                    sys.exit(1)
            except StopIteration:
                print("Error: -p requires a protocol name (udp or tcp).")
                sys.exit(1)
        else:
            if executable_path is None:
                executable_path = arg
            else:
                print("Error: Unexpected argument or executable path already set.")
                sys.exit(1)

    if executable_path is None:
        print("Error: Path to executable is required.")
        sys.exit(1)

    # Now call run_tests with the collected options
    run_tests(executable_path, udp=udp, tcp=tcp, test_case=test_case)
