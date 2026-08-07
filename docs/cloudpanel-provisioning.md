# CloudPanel one-click WordPress provisioning

The dashboard provisions an active Cloudflare zone with one click. Celery first
creates unproxied DNS records, then calls a restricted host-side CloudPanel
wrapper over SSH. The wrapper creates the PHP site and database, installs
WordPress, creates an application password, and requests the certificate. The
worker then enables the Cloudflare proxy and verifies WordPress authentication.

## 1. Confirm the CloudPanel template

Run these on the CloudPanel host:

```bash
sudo clpctl vhost-templates:list
sudo clpctl vhost-template:view --name='WordPress'
```

For the standard CloudPanel `WordPress` template, the **Root Directory**
column is blank. That means these values are correct and no `/public` suffix is
needed:

```dotenv
CLOUDPANEL_VHOST_TEMPLATE=WordPress
CLOUDPANEL_DOCUMENT_ROOT_TEMPLATE=/home/{site_user}/htdocs/{domain}
```

## 2. Create the restricted SSH identity

The dashboard and CloudPanel are on different hosts. Generate the private key on
the **dashboard host** (the machine running this Docker Compose project). From
the project directory, run:

```bash
mkdir -p .secrets/cloudpanel
chmod 700 .secrets/cloudpanel
ssh-keygen -t ed25519 -N '' -f .secrets/cloudpanel/id_ed25519
ssh hm@152.53.53.101 'mkdir -p ~/wp-manager-provisioner-setup'
scp scripts/wp-manager-cloudpanel \
  scripts/install-cloudpanel-provisioner.sh \
  .secrets/cloudpanel/id_ed25519.pub \
  hm@152.53.53.101:~/wp-manager-provisioner-setup/
```

Then connect to the **CloudPanel host** and install the restricted wrapper:

```bash
ssh hm@152.53.53.101
cd ~/wp-manager-provisioner-setup
chmod +x install-cloudpanel-provisioner.sh wp-manager-cloudpanel
sudo ./install-cloudpanel-provisioner.sh id_ed25519.pub
exit
```

The installer creates `wp-provisioner`. Its key is forced to execute only
`/usr/local/sbin/wp-manager-cloudpanel`; it cannot request an interactive shell
or run arbitrary commands. The wrapper accepts validated JSON on standard input
and keeps root-only idempotency markers under
`/var/lib/wp-manager-provisioning`.

Capture the SSH host key for the remote CloudPanel server using the exact IP
configured in `CLOUDPANEL_SSH_HOST`:

```bash
docker compose run --rm --no-deps celery_worker \
  ssh-keyscan -H 152.53.53.101 > .secrets/cloudpanel/known_hosts
chmod 600 .secrets/cloudpanel/id_ed25519 .secrets/cloudpanel/known_hosts
```

The dashboard host must be able to reach TCP port 22 on this IP. Restrict the
CloudPanel firewall to the dashboard server IP whenever possible.

## 3. Configure the environment

Add these values to `.env`:

```dotenv
CLOUDPANEL_ORIGIN_IP=152.53.53.101
CLOUDPANEL_SSH_HOST=152.53.53.101
CLOUDPANEL_SSH_PORT=22
CLOUDPANEL_SSH_USER=wp-provisioner
CLOUDPANEL_SSH_KEY_PATH=/run/secrets/cloudpanel/id_ed25519
CLOUDPANEL_KNOWN_HOSTS_PATH=/run/secrets/cloudpanel/known_hosts
CLOUDPANEL_WRAPPER_COMMAND=sudo -n /usr/local/sbin/wp-manager-cloudpanel
CLOUDPANEL_PROVISION_TIMEOUT=900
CLOUDPANEL_PHP_VERSION=8.3
CLOUDPANEL_VHOST_TEMPLATE=WordPress
CLOUDPANEL_DOCUMENT_ROOT_TEMPLATE=/home/{site_user}/htdocs/{domain}
CLOUDPANEL_ADMIN_EMAIL=you@example.com
PROVISIONING_ENCRYPTION_KEY=replace-with-a-fernet-key
```

Generate the encryption key once and keep it stable across deployments:

```bash
docker compose run --rm --no-deps web \
  python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Do not rotate that key while a provisioning job is unfinished; its temporary
CloudPanel, database, and WordPress credentials are encrypted with it.

## 4. Deploy

```bash
docker compose build web celery_worker celery_beat
docker compose up -d
docker compose exec web python manage.py migrate
```

Open **Settings → Cloudflare**, save a token with Zone Read and DNS Edit access,
then click **Install WordPress** beside an active zone. The row reports durable
progress and can be safely reloaded. Failed jobs expose a Retry action.

## Recovery notes

- Repeated task delivery is safe: the host wrapper records each successful
  provisioning stage and resumes after it.
- Existing DNS records of the same type are updated. An incompatible record
  type fails visibly instead of being deleted.
- DNS stays unproxied until CloudPanel has requested the certificate.
- A failed job remains attached to its site and can be retried; it is never
  silently replaced with a second installation.
