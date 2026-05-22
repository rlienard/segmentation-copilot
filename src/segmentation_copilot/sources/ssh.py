"""SSH-based syslog source using paramiko."""

from __future__ import annotations

import shlex
from datetime import datetime
from typing import Iterator

from .base import LogSource, LogSourceConfig


class SSHSource(LogSource):
    """Connect to a syslog collector over SSH and grep the relevant log file(s).

    Required options:
        host: hostname or IP
        username: SSH user
        log_path: remote path to syslog file (or a glob, e.g. /var/log/network/*.log)
    Optional:
        port: SSH port (default 22)
        password: SSH password (use key-based auth when possible)
        key_filename: path to private key
        grep_pattern: extra grep filter (default 'SGACLHIT')
    """

    def __init__(
        self,
        host: str,
        username: str,
        log_path: str,
        port: int = 22,
        password: str | None = None,
        key_filename: str | None = None,
        grep_pattern: str = "SGACLHIT",
    ):
        self.host = host
        self.username = username
        self.log_path = log_path
        self.port = port
        self.password = password
        self.key_filename = key_filename
        self.grep_pattern = grep_pattern

    @classmethod
    def from_config(cls, config: LogSourceConfig) -> "SSHSource":
        opts = config.options
        missing = [k for k in ("host", "username", "log_path") if not opts.get(k)]
        if missing:
            raise ValueError(f"SSHSource requires: {missing}")
        return cls(
            host=opts["host"],
            username=opts["username"],
            log_path=opts["log_path"],
            port=int(opts.get("port", 22)),
            password=opts.get("password"),
            key_filename=opts.get("key_filename"),
            grep_pattern=opts.get("grep_pattern", "SGACLHIT"),
        )

    def fetch(self, start: datetime, end: datetime) -> Iterator[str]:
        # Import paramiko lazily so the package imports cleanly without it.
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            key_filename=self.key_filename,
            timeout=15,
        )
        try:
            # zgrep handles both plain and .gz rotated logs.
            cmd = f"zgrep -h {shlex.quote(self.grep_pattern)} {self.log_path}"
            _, stdout, _ = client.exec_command(cmd)
            from ..parser import _parse_ts  # local import to avoid cycle at module load

            for line in stdout:
                ts = _parse_ts(line)
                if ts is None:
                    yield line
                    continue
                if ts.year == 1900:
                    ts = ts.replace(year=start.year)
                if start <= ts <= end:
                    yield line
        finally:
            client.close()
