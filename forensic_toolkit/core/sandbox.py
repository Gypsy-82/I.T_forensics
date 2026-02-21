"""
Sandbox & Confinement Module
=============================
Provides an isolated workspace for forensic analysis.

- Files are copied into a temporary directory for analysis
- Original files are NEVER modified
- Path traversal is blocked
- No network access from within the sandbox
- Automatic cleanup on exit
"""

import os
import sys
import shutil
import tempfile
import socket


class Sandbox:
    """Isolated sandbox environment for safe file analysis."""

    def __init__(self):
        self._sandbox_dir = None
        self._original_paths = {}
        self._network_blocked = False
        self._original_socket = None

    @property
    def sandbox_dir(self):
        return self._sandbox_dir

    def create(self):
        """Create the sandbox temporary directory."""
        self._sandbox_dir = tempfile.mkdtemp(prefix="forensic_sandbox_")
        os.chmod(self._sandbox_dir, 0o700)
        return self._sandbox_dir

    def block_network(self):
        """Disable all network access by monkey-patching socket."""
        if self._network_blocked:
            return

        self._original_socket = socket.socket

        def blocked_socket(*args, **kwargs):
            raise OSError(
                "Network access is blocked inside the Forensic Toolkit sandbox."
            )

        socket.socket = blocked_socket
        self._network_blocked = True

    def restore_network(self):
        """Restore network access (called during cleanup)."""
        if self._network_blocked and self._original_socket:
            socket.socket = self._original_socket
            self._network_blocked = False

    def import_file(self, file_path):
        """
        Copy a file into the sandbox for analysis.

        Returns the sandbox path to the copied file.
        Raises an error if the path is invalid or attempts traversal.
        """
        if not self._sandbox_dir:
            raise RuntimeError("Sandbox has not been created. Call create() first.")

        # Resolve to absolute path
        real_path = os.path.realpath(file_path)

        # Validate the file exists and is a regular file
        if not os.path.exists(real_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        if not os.path.isfile(real_path):
            raise ValueError(f"Not a regular file: {file_path}")

        # Block access to the sandbox directory itself (prevent circular import)
        if real_path.startswith(self._sandbox_dir):
            raise ValueError("Cannot import files from within the sandbox.")

        # Copy file into sandbox preserving the original filename
        filename = os.path.basename(real_path)

        # Handle duplicate filenames by adding a suffix
        sandbox_path = os.path.join(self._sandbox_dir, filename)
        counter = 1
        base, ext = os.path.splitext(filename)
        while os.path.exists(sandbox_path):
            sandbox_path = os.path.join(
                self._sandbox_dir, f"{base}_{counter}{ext}"
            )
            counter += 1

        shutil.copy2(real_path, sandbox_path)

        # Make the sandbox copy read-only
        os.chmod(sandbox_path, 0o444)

        # Track mapping: sandbox_path -> original_path
        self._original_paths[sandbox_path] = real_path

        return sandbox_path

    def get_original_path(self, sandbox_path):
        """Get the original file path for a sandboxed file."""
        return self._original_paths.get(sandbox_path, sandbox_path)

    def validate_path(self, path):
        """Ensure a path is confined within the sandbox."""
        if not self._sandbox_dir:
            return False
        real = os.path.realpath(path)
        return real.startswith(os.path.realpath(self._sandbox_dir))

    def cleanup(self):
        """Remove the sandbox directory and all its contents."""
        self.restore_network()
        if self._sandbox_dir and os.path.exists(self._sandbox_dir):
            # Restore write permissions so we can delete
            for root, dirs, files in os.walk(self._sandbox_dir):
                for f in files:
                    fp = os.path.join(root, f)
                    os.chmod(fp, 0o644)
            shutil.rmtree(self._sandbox_dir, ignore_errors=True)
            self._sandbox_dir = None
            self._original_paths.clear()

    def __enter__(self):
        self.create()
        self.block_network()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
