# WordPress design templates

The dashboard lists the templates available on each WordPress site. Selecting a template stores one WordPress option. The switch leaves posts, categories, permalinks, and Reading settings in place. **Restore original design** turns off the design styles and front-page layout.

## Staging setup

1. Zip the `wordpress/wp-manager-designs` directory with its top-level folder, then upload and activate it through **Plugins → Add New → Upload Plugin** on the staging site.
2. Add the staging domain as a separate site in the dashboard. Use the WordPress username and an Application Password for an account with the `edit_theme_options` capability.
3. Open **Design Templates** from the staging site's dashboard page. Apply each of the three templates, check the homepage and a typical post, then test **Restore original design**.
4. If the host caches full HTML pages, connect its page-cache purge to the `wp_manager_design_changed` action before deploying. The action receives the new and previous template IDs.

The initial templates support GeneratePress and its child themes. They replace the first page of the latest-posts feed when it is the homepage. A static front page keeps its existing layout and inherits the design styles.

## Site-specific templates

The plugin ships Editorial, Journal, and Handbook. A site can register a catalog of three to five designs using the `wp_manager_design_templates` filter in its child theme. Use stable IDs and provide a name and description for each. The active design adds a `wpm-design-{id}` body class for the site's design styles. Keep the same ID across releases so the existing selection continues to work.
