"""
LLMPot — SSH Honeypot Server
Paramiko-based SSH server that emulates a realistic Linux SSH endpoint.
"""

import socket
import threading
import time
import paramiko
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (SSH_HOST, SSH_PORT, SSH_HOST_KEY_FILE, SSH_BANNER,
                    MAX_CONNECTIONS, CONNECTION_TIMEOUT)
from honeypot.auth_handler import AuthHandler
from honeypot.session_handler import SessionHandler
from database.db_manager import DatabaseManager
from utils.logger import get_logger
from utils.geoip import GeoIPLookup
from utils.helpers import generate_session_id

logger = get_logger("ssh")


class HoneypotSSHServer(paramiko.ServerInterface):
    """Paramiko ServerInterface implementation for the honeypot."""

    def __init__(self, auth_handler: AuthHandler, client_ip: str,
                 client_port: int, session_id: str):
        self.auth_handler = auth_handler
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_id = session_id
        self.username = None
        self.password = None
        self.authenticated = False
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password

        # Log auth attempt to DB
        db = DatabaseManager()
        db.log_auth_attempt(
            attacker_ip=self.client_ip,
            attacker_port=self.client_port,
            username=username,
            password=password,
            success=False,
            session_id=self.session_id,
        )

        if self.auth_handler.check_credentials(username, password, self.client_ip):
            self.authenticated = True
            # Update auth attempt as successful
            db.log_auth_attempt(
                attacker_ip=self.client_ip,
                attacker_port=self.client_port,
                username=username,
                password=password,
                success=True,
                session_id=self.session_id,
            )
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Always reject public key auth
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True

    def check_channel_env_request(self, channel, name, value):
        return True


class SSHHoneypotServer:
    """Main SSH honeypot server managing connections."""

    def __init__(self, host: str = SSH_HOST, port: int = SSH_PORT):
        self.host = host
        self.port = port
        self.auth_handler = AuthHandler()
        self.db = DatabaseManager()
        self.geoip = GeoIPLookup()
        self._active_connections = 0
        self._lock = threading.Lock()
        self._running = False
        self._server_socket = None
        self._host_key = None

    def _load_host_key(self):
        """Load the SSH host key."""
        key_path = Path(SSH_HOST_KEY_FILE)
        if not key_path.exists():
            logger.info("Host key not found, generating new key...")
            from generate_key import generate_host_key
            generate_host_key(str(key_path))

        self._host_key = paramiko.RSAKey.from_private_key_file(str(key_path))
        logger.info(f"Loaded host key: {self._host_key.get_fingerprint().hex()}")

    def start(self):
        """Start the SSH honeypot server."""
        self._load_host_key()
        self._running = True

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self._server_socket.bind((self.host, self.port))
        except OSError as e:
            logger.error(f"Cannot bind to {self.host}:{self.port} — {e}")
            logger.info("Try running with sudo or use a port > 1024")
            return

        self._server_socket.listen(MAX_CONNECTIONS)
        self._server_socket.settimeout(1.0)

        logger.info(f"═══════════════════════════════════════════════════")
        logger.info(f"  🍯 LLMPot SSH Honeypot Server Started")
        logger.info(f"  📡 Listening on {self.host}:{self.port}")
        logger.info(f"  🔑 Host key fingerprint: {self._host_key.get_fingerprint().hex()}")
        logger.info(f"  🚀 Max connections: {MAX_CONNECTIONS}")
        logger.info(f"═══════════════════════════════════════════════════")

        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.error("Socket accept error")
                break

            # Check connection limit
            with self._lock:
                if self._active_connections >= MAX_CONNECTIONS:
                    logger.warning(
                        f"Max connections reached ({MAX_CONNECTIONS}), "
                        f"rejecting {addr[0]}:{addr[1]}"
                    )
                    client_socket.close()
                    continue
                self._active_connections += 1

            # Handle connection in a new thread
            thread = threading.Thread(
                target=self._handle_connection,
                args=(client_socket, addr),
                daemon=True,
            )
            thread.start()

    def stop(self):
        """Stop the SSH honeypot server."""
        logger.info("Shutting down SSH honeypot server...")
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        logger.info("Server stopped.")

    def _handle_connection(self, client_socket: socket.socket, addr: tuple):
        """Handle a single SSH connection."""
        client_ip, client_port = addr
        session_id = generate_session_id()

        logger.info(f"━━━ New connection from {client_ip}:{client_port} "
                     f"[session: {session_id[:8]}] ━━━")

        # GeoIP lookup
        geo_data = self.geoip.lookup(client_ip)
        geo_str = ""
        if geo_data:
            geo_str = f" ({geo_data.get('country', '?')}, {geo_data.get('city', '?')})"
            logger.info(f"GeoIP: {client_ip} → {geo_str}")

        transport = None
        try:
            # Set up Paramiko transport
            transport = paramiko.Transport(client_socket)
            transport.local_version = SSH_BANNER
            transport.add_server_key(self._host_key)

            # Create server interface
            server = HoneypotSSHServer(
                self.auth_handler, client_ip, client_port, session_id
            )

            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                logger.warning(f"SSH negotiation failed for {client_ip}: {e}")
                return

            # Wait for authentication (up to 30 seconds)
            channel = transport.accept(30)
            if channel is None:
                logger.info(f"No channel from {client_ip} — timeout")
                return

            if not server.authenticated:
                logger.info(f"Auth failed for {client_ip}, closing")
                channel.close()
                return

            # Create session record
            self.db.create_session(
                session_id=session_id,
                attacker_ip=client_ip,
                attacker_port=client_port,
                username=server.username,
                password=server.password,
                auth_success=True,
                geo_data=geo_data,
            )

            logger.warning(
                f"🔓 AUTH SUCCESS: {server.username}@{client_ip}{geo_str} "
                f"[session: {session_id[:8]}]"
            )

            # Wait for shell/pty request
            server.event.wait(10)

            # Handle interactive session
            session = SessionHandler(session_id, server.username, client_ip)
            self._interactive_session(channel, session)

        except paramiko.SSHException as e:
            logger.warning(f"SSH error for {client_ip}: {e}")
        except ConnectionResetError:
            logger.info(f"Connection reset by {client_ip}")
        except Exception as e:
            logger.error(f"Unexpected error for {client_ip}: {e}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            client_socket.close()

            with self._lock:
                self._active_connections -= 1

            logger.info(f"Connection closed: {client_ip}:{client_port} "
                         f"[session: {session_id[:8]}]")

    def _interactive_session(self, channel, session: SessionHandler):
        """Handle interactive shell session."""
        try:
            # Send MOTD
            motd = session.get_motd()
            channel.sendall(motd.encode("utf-8"))

            # Send initial prompt
            prompt = session.get_prompt()
            channel.sendall(prompt.encode("utf-8"))

            # Command buffer
            cmd_buffer = ""
            channel.settimeout(CONNECTION_TIMEOUT)

            while session.is_active:
                try:
                    data = channel.recv(4096)
                    if not data:
                        break

                    text = data.decode("utf-8", errors="ignore")

                    for char in text:
                        if char == "\r" or char == "\n":
                            # Process command
                            channel.sendall(b"\r\n")

                            if cmd_buffer.strip():
                                output, should_exit = session.handle_command(
                                    cmd_buffer.strip()
                                )

                                if output:
                                    # Send output line by line
                                    for line in output.split("\n"):
                                        channel.sendall(
                                            (line + "\r\n").encode("utf-8")
                                        )

                                if should_exit:
                                    break

                            cmd_buffer = ""
                            prompt = session.get_prompt()
                            channel.sendall(prompt.encode("utf-8"))

                        elif char == "\x7f" or char == "\x08":
                            # Backspace
                            if cmd_buffer:
                                cmd_buffer = cmd_buffer[:-1]
                                channel.sendall(b"\x08 \x08")

                        elif char == "\x03":
                            # Ctrl+C
                            channel.sendall(b"^C\r\n")
                            cmd_buffer = ""
                            prompt = session.get_prompt()
                            channel.sendall(prompt.encode("utf-8"))

                        elif char == "\x04":
                            # Ctrl+D (EOF)
                            break

                        elif char == "\t":
                            # Tab (ignore)
                            pass

                        elif ord(char) >= 32:
                            # Printable character
                            cmd_buffer += char
                            channel.sendall(char.encode("utf-8"))

                except socket.timeout:
                    channel.sendall(b"\r\nConnection timed out.\r\n")
                    break
                except Exception:
                    break

        except Exception as e:
            logger.error(f"Session error: {e}")
        finally:
            session.end_session()
            try:
                channel.close()
            except Exception:
                pass
