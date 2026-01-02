import atexit
import re
import subprocess
import threading
import signal
import os
from collections import deque
from contextlib import contextmanager

from app import logger
from app.singbox.config import SingBoxConfig
from config import DEBUG


class SingBoxCore:
    def __init__(
        self,
        executable_path: str = "/usr/local/bin/sing-box",
        assets_path: str = "/usr/local/share/sing-box",
    ):
        self.executable_path = executable_path
        self.assets_path = assets_path

        self.version = self.get_version()
        self.process = None
        self.restarting = False
        self._config_path = None

        self._logs_buffer = deque(maxlen=100)
        self._temp_log_buffers = {}
        self._on_start_funcs = []
        self._on_stop_funcs = []
        self._env = {"SINGBOX_ASSETS_PATH": assets_path}

        atexit.register(lambda: self.stop() if self.started else None)

    def get_version(self):
        try:
            cmd = [self.executable_path, "version"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(
                "utf-8"
            )
            m = re.search(r"sing-box version (\d+\.\d+\.\d+)", output)
            if m:
                return m.group(1)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def __capture_process_logs(self):
        def capture_and_debug_log():
            while self.process:
                output = self.process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)
                    logger.debug(output)

                elif not self.process or self.process.poll() is not None:
                    break

        def capture_only():
            while self.process:
                output = self.process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)

                elif not self.process or self.process.poll() is not None:
                    break

        if DEBUG:
            threading.Thread(target=capture_and_debug_log, daemon=True).start()
        else:
            threading.Thread(target=capture_only, daemon=True).start()

    @contextmanager
    def get_logs(self):
        buf = deque(self._logs_buffer, maxlen=100)
        buf_id = id(buf)
        try:
            self._temp_log_buffers[buf_id] = buf
            yield buf
        finally:
            del self._temp_log_buffers[buf_id]
            del buf

    @property
    def started(self):
        if not self.process:
            return False

        if self.process.poll() is None:
            return True

        return False

    def start(self, config: SingBoxConfig):
        if self.started is True:
            raise RuntimeError("Sing-box is started already")

        # Write config to temporary file
        import tempfile
        import json

        fd, self._config_path = tempfile.mkstemp(suffix=".json", prefix="singbox_")
        with os.fdopen(fd, "w") as f:
            f.write(config.to_json())

        cmd = [self.executable_path, "run", "-c", self._config_path]

        self.process = subprocess.Popen(
            cmd,
            env={**os.environ, **self._env},
            stdin=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        logger.warning(f"Sing-box core {self.version} started")

        self.__capture_process_logs()

        # execute on start functions
        for func in self._on_start_funcs:
            threading.Thread(target=func, daemon=True).start()

    def stop(self):
        if not self.started:
            return

        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()

        self.process = None
        logger.warning("Sing-box core stopped")

        # Clean up config file
        if self._config_path and os.path.exists(self._config_path):
            try:
                os.unlink(self._config_path)
            except Exception:
                pass
            self._config_path = None

        # execute on stop functions
        for func in self._on_stop_funcs:
            threading.Thread(target=func, daemon=True).start()

    def restart(self, config: SingBoxConfig):
        if self.restarting is True:
            return

        try:
            self.restarting = True
            logger.warning("Restarting Sing-box core...")
            self.stop()
            self.start(config)
        finally:
            self.restarting = False

    def reload(self, config: SingBoxConfig):
        """Reload configuration by rewriting config file and sending SIGHUP."""
        if not self.started:
            return self.start(config)

        # Write new config
        if self._config_path and os.path.exists(self._config_path):
            with open(self._config_path, "w") as f:
                f.write(config.to_json())

            # Send SIGHUP to reload config
            try:
                os.kill(self.process.pid, signal.SIGHUP)
                logger.info("Sing-box config reloaded via SIGHUP")
            except Exception as e:
                logger.error(f"Failed to reload sing-box config: {e}")
                # Fall back to restart
                self.restart(config)
        else:
            self.restart(config)

    def on_start(self, func: callable):
        self._on_start_funcs.append(func)
        return func

    def on_stop(self, func: callable):
        self._on_stop_funcs.append(func)
        return func
