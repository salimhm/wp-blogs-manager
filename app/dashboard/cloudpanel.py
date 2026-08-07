"""Restricted SSH client for the host-side CloudPanel provisioner."""

import json
import os
import subprocess

from django.conf import settings


class CloudPanelError(RuntimeError):
    pass


class CloudPanelClient:
    def __init__(self):
        self.host = settings.CLOUDPANEL_SSH_HOST
        self.port = settings.CLOUDPANEL_SSH_PORT
        self.user = settings.CLOUDPANEL_SSH_USER
        self.key_path = settings.CLOUDPANEL_SSH_KEY_PATH
        self.known_hosts_path = settings.CLOUDPANEL_KNOWN_HOSTS_PATH
        self.wrapper_command = settings.CLOUDPANEL_WRAPPER_COMMAND
        self.timeout = settings.CLOUDPANEL_PROVISION_TIMEOUT

    def _command(self):
        return [
            'ssh',
            '-T',
            '-p',
            str(self.port),
            '-i',
            self.key_path,
            '-o',
            'BatchMode=yes',
            '-o',
            'IdentitiesOnly=yes',
            '-o',
            'StrictHostKeyChecking=yes',
            '-o',
            f'UserKnownHostsFile={self.known_hosts_path}',
            f'{self.user}@{self.host}',
            self.wrapper_command,
        ]

    def provision(self, payload):
        missing = [
            path for path in (self.key_path, self.known_hosts_path)
            if not os.path.isfile(path)
        ]
        if missing:
            raise CloudPanelError(
                'CloudPanel SSH files are missing: ' + ', '.join(missing)
            )

        try:
            completed = subprocess.run(
                self._command(),
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CloudPanelError(f'Could not run CloudPanel provisioner: {exc}') from exc

        output = completed.stdout.strip().splitlines()
        response = None
        if output:
            try:
                response = json.loads(output[-1])
            except json.JSONDecodeError:
                response = None

        if completed.returncode != 0 or not response or not response.get('success'):
            safe_error = (
                (response or {}).get('error')
                or completed.stderr.strip()
                or 'CloudPanel provisioner failed without a structured response'
            )
            raise CloudPanelError(str(safe_error)[:1000])

        return response
