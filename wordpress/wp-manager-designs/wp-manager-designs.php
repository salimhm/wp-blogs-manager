<?php
/**
 * Plugin Name: WP Manager Designs
 * Description: Switches the presentation of GeneratePress sites from WP Blogs Manager.
 * Version: 0.1.0
 * Requires at least: 5.9
 * Requires PHP: 7.4
 */

namespace WPManagerDesigns;

if (!defined('ABSPATH')) {
    exit;
}

const OPTION = 'wp_manager_design_template';
const VERSION = '0.1.0';

function templates() {
    if (get_template() !== 'generatepress') {
        return array();
    }

    $defaults = array(
        'editorial' => array(
            'name' => 'Editorial',
            'description' => 'Cream and olive, with a split feature and a three-column guide grid.',
        ),
        'journal' => array(
            'name' => 'Journal',
            'description' => 'Warm terracotta, a stacked feature, and a single-column reading list.',
        ),
        'handbook' => array(
            'name' => 'Handbook',
            'description' => 'Ink blue, a compact feature, and a two-column guide index.',
        ),
    );
    $site_templates = apply_filters('wp_manager_design_templates', $defaults);
    if (!is_array($site_templates) || count($site_templates) < 3 || count($site_templates) > 5) {
        return $defaults;
    }

    foreach ($site_templates as $id => $template) {
        if (!is_string($id) || $id === 'default' || !preg_match('/^[a-z][a-z0-9-]*$/D', $id)
            || !is_array($template) || !is_string($template['name'] ?? null)
            || !is_string($template['description'] ?? null)) {
            return $defaults;
        }
    }
    return $site_templates;
}

function active_template() {
    $active = get_option(OPTION, 'default');
    return is_string($active) && isset(templates()[$active]) ? $active : 'default';
}

function design_response() {
    $choices = array();
    foreach (templates() as $id => $template) {
        $choices[] = array('id' => $id) + $template;
    }

    return rest_ensure_response(array('active' => active_template(), 'templates' => $choices));
}

function apply_template(\WP_REST_Request $request) {
    $template = $request->get_param('template');
    if (!is_string($template) || ($template !== 'default' && !isset(templates()[$template]))) {
        return new \WP_Error('unknown_design', 'This design template is unavailable.', array('status' => 400));
    }

    $previous = get_option(OPTION, 'default');
    if ($template !== $previous) {
        if (!update_option(OPTION, $template, false) && get_option(OPTION, 'default') !== $template) {
            return new \WP_Error('design_save_failed', 'Could not save the design.', array('status' => 500));
        }
        do_action('wp_manager_design_changed', $template, $previous);
    }
    return design_response();
}

function can_manage_designs() {
    return current_user_can('edit_theme_options');
}

add_action('rest_api_init', function () {
    register_rest_route('wp-manager/v1', '/design', array(
        array(
            'methods' => \WP_REST_Server::READABLE,
            'callback' => __NAMESPACE__ . '\\design_response',
            'permission_callback' => __NAMESPACE__ . '\\can_manage_designs',
        ),
        array(
            'methods' => \WP_REST_Server::CREATABLE,
            'callback' => __NAMESPACE__ . '\\apply_template',
            'permission_callback' => __NAMESPACE__ . '\\can_manage_designs',
            'args' => array('template' => array('type' => 'string', 'required' => true)),
        ),
    ));
});

function kitchen_wisdom() {
    $hostname = wp_parse_url(home_url('/'), PHP_URL_HOST);
    return $hostname === 'kitchenwisdom.info'
        || (is_string($hostname) && substr($hostname, -19) === '.kitchenwisdom.info')
        || sanitize_title(get_bloginfo('name')) === 'kitchenwisdom'
        || sanitize_title(get_bloginfo('name')) === 'kitchen-wisdom';
}

add_filter('body_class', function ($classes) {
    $active = active_template();
    if ($active !== 'default') {
        $classes[] = 'wpm-design';
        $classes[] = 'wpm-design-' . $active;
        if (kitchen_wisdom()) {
            $classes[] = 'wpm-kitchen-wisdom';
        }
    }
    return $classes;
});

add_action('wp_enqueue_scripts', function () {
    if (active_template() !== 'default') {
        wp_enqueue_style('wp-manager-designs', plugins_url('assets/designs.css', __FILE__), array(), VERSION);
    }
}, 30);

add_filter('template_include', function ($template) {
    if (is_front_page() && is_home() && !is_paged() && active_template() !== 'default') {
        return __DIR__ . '/front-page.php';
    }
    return $template;
});

function selected_posts() {
    global $wp_query;
    $latest = $wp_query->posts;
    if (!kitchen_wisdom()) {
        return $latest;
    }

    $curated = array();
    $slugs = array_merge(
        array('the-ultimate-tuna-steak-guide-slicing-seasoning-cooking-storing-serving-secrets'),
        array_keys(kitchen_topics())
    );
    foreach ($slugs as $slug) {
        $post = get_page_by_path($slug, OBJECT, 'post');
        if ($post && $post->post_status === 'publish' && $post->post_password === '') {
            $curated[$post->ID] = $post;
        }
    }
    return array_values($curated + array_column($latest, null, 'ID'));
}

function kitchen_topics() {
    return array(
        'the-ultimate-guide-to-grilling-beets-techniques-seasonings-and-health-benefits' => 'Cooking techniques',
        'the-egg-mystery-unveiled-a-complete-guide-to-black-spots-green-rings-and-safe-consumption' => 'Ingredients',
        'the-ultimate-breville-espresso-machine-guide-cleaning-grinding-maintenance-and-mastering-milk-based-drinks' => 'Kitchen tools',
    );
}
