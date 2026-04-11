"""
px_auth.py — Authentication flow: purelogin → paramiko SSH to Fuse2.

Auth flow:
    1. Run `purelogin --force-login` subprocess (SSO — prompts interactively)
    2. Connect via paramiko with SSH AgentRequestHandler to fuse jump host
    3. Return open paramiko SSHClient (caller must .close() when done)

Credentials are captured at runtime only — never written to disk beyond active session.
"""
from __future__ import annotations

import logging
import os
import subprocess

import paramiko
from paramiko.agent import AgentRequestHandler

log = logging.getLogger(__name__)

FUSE_HOST = "fuse"
FUSE_PORT = 22
DEFAULT_USERNAME = os.environ.get("USER", os.environ.get("LOGNAME", ""))


def purelogin() -> None:
    """
    Run purelogin --force-login interactively.
    Raises subprocess.CalledProcessError on non-zero exit.
    Raises FileNotFoundError if purelogin is not in PATH.
    """
    log.info("Running purelogin --force-login ...")
    subprocess.run(["purelogin", "--force-login"], check=True)
    log.info("purelogin succeeded.")


def auth_flow(
    host: str = FUSE_HOST,
    port: int = FUSE_PORT,
    username: str | None = None,
) -> paramiko.SSHClient:
    """
    Full auth flow: purelogin → SSH connect to Fuse2 jump host.

    Returns an open paramiko.SSHClient with agent forwarding enabled.
    Caller is responsible for calling .close() when done.

    Raises RuntimeError on auth or connection failure.
    """
    if username is None:
        username = DEFAULT_USERNAME or os.environ.get("USER", "")

    # Step 1: purelogin SSO
    try:
        purelogin()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.warning(f"purelogin failed or not in PATH: {e}. Attempting SSH without purelogin.")

    # Step 2: SSH to Fuse2 with agent forwarding
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    log.info(f"Connecting to {username}@{host}:{port} ...")

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            allow_agent=True,       # use ssh-agent keys
            look_for_keys=True,     # fall back to ~/.ssh/id_*
            timeout=30,
        )
    except paramiko.AuthenticationException as e:
        client.close()
        raise RuntimeError(
            f"SSH authentication failed for {username}@{host}. "
            "Ensure SSH agent is running and loaded: ssh-add ~/.ssh/id_rsa"
        ) from e
    except Exception as e:
        client.close()
        raise RuntimeError(f"SSH connection to {host} failed: {e}") from e

    # Enable agent forwarding on the session channel
    transport = client.get_transport()
    if transport:
        session = transport.open_session()
        AgentRequestHandler(session)

    log.info(f"Connected to {host}.")
    return client
