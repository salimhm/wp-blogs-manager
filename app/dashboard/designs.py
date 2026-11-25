"""WordPress design selection for a registered site."""

import requests


class DesignError(Exception):
    pass


def wordpress_design(site, template=None):
    if not site.wp_app_password:
        raise DesignError('Set a WordPress Application Password to manage designs.')

    endpoint = f'https://{site.domain}/wp-json/wp-manager/v1/design'
    options = {
        'auth': (site.wp_username, site.wp_app_password),
        'timeout': (4, 8),
        'allow_redirects': False,
    }
    try:
        if template is None:
            response = requests.get(endpoint, **options)
        else:
            response = requests.post(endpoint, json={'template': template}, **options)
    except requests.RequestException as exc:
        raise DesignError('WordPress did not respond. Reload to check the active design.') from exc

    if response.status_code == 404:
        raise DesignError('Activate the WP Manager Designs plugin on this WordPress site.')
    if response.status_code in (401, 403):
        raise DesignError('The WordPress account needs permission to manage appearance.')
    if response.status_code == 400:
        raise DesignError('This template is unavailable for the current WordPress theme.')
    if response.status_code != 200:
        raise DesignError('WordPress could not complete the design request. Reload to check the active design.')

    try:
        design = response.json()
        valid = (
            isinstance(design, dict)
            and isinstance(design.get('active'), str)
            and isinstance(design.get('templates'), list)
            and all(
                isinstance(item, dict)
                and all(isinstance(item.get(key), str) for key in ('id', 'name', 'description'))
                for item in design['templates']
            )
        )
    except ValueError as exc:
        raise DesignError('WordPress returned an invalid design response.') from exc
    if not valid:
        raise DesignError('WordPress returned an invalid design response.')
    if template is not None and design['active'] != template:
        raise DesignError('WordPress reports a different active design. Reload to check the current selection.')
    return design
