<?php
namespace WPManagerDesigns;

if (!defined('ABSPATH')) {
    exit;
}

$posts_to_show = selected_posts();
$featured = array_shift($posts_to_show);
$is_kitchen = kitchen_wisdom();
$tuna_feature = $is_kitchen && $featured
    && $featured->post_name === 'the-ultimate-tuna-steak-guide-slicing-seasoning-cooking-storing-serving-secrets';
$categories = get_categories(array(
    'exclude' => (int) get_option('default_category'),
    'hide_empty' => true,
    'number' => 5,
    'orderby' => 'count',
    'order' => 'DESC',
));
$topics = array();
foreach ($categories as $category) {
    $topics[] = array('url' => get_category_link($category), 'name' => $category->name);
}
if (!$topics && $is_kitchen) {
    $labels = kitchen_topics();
    foreach ($posts_to_show as $guide) {
        if (isset($labels[$guide->post_name])) {
            $topics[] = array('url' => get_permalink($guide), 'name' => $labels[$guide->post_name]);
        }
    }
}

get_header();
?>
<main id="main" class="site-main wpm-home">
    <section class="wpm-hero">
        <div class="wpm-wrap wpm-hero-inner">
            <div class="wpm-intro">
                <h1><?php echo esc_html($is_kitchen ? 'Cook with confidence.' : get_bloginfo('name')); ?></h1>
                <?php $description = $is_kitchen
                    ? 'Practical guides to ingredients, cooking techniques, and the tools you use every day.'
                    : get_bloginfo('description'); ?>
                <?php if ($description) : ?>
                    <p><?php echo esc_html($description); ?></p>
                <?php endif; ?>
                <?php if ($posts_to_show) : ?>
                    <a class="wpm-button" href="#wpm-guides">Explore the guides <span aria-hidden="true">↓</span></a>
                <?php endif; ?>
            </div>
            <?php if ($featured) : ?>
                <figure class="wpm-feature">
                    <?php if (has_post_thumbnail($featured)) : ?>
                        <?php echo get_the_post_thumbnail($featured, 'large', array('fetchpriority' => 'high', 'loading' => 'eager')); ?>
                    <?php elseif ($tuna_feature) : ?>
                        <img src="<?php echo esc_url(plugins_url('assets/tuna-steak.jpg', __FILE__)); ?>" alt="Sliced seared tuna steak with lemon and herbs" width="1536" height="1024" fetchpriority="high">
                    <?php endif; ?>
                    <figcaption><a href="<?php echo esc_url(get_permalink($featured)); ?>"><?php echo esc_html($tuna_feature ? 'How to cook tuna steak' : get_the_title($featured)); ?> <span aria-hidden="true">↗</span></a></figcaption>
                </figure>
            <?php endif; ?>
        </div>
    </section>

    <?php if ($topics) : ?>
        <section class="wpm-wrap wpm-section" aria-labelledby="wpm-topics">
            <h2 id="wpm-topics">Browse by topic</h2>
            <ul class="wpm-topics">
                <?php foreach ($topics as $topic) : ?>
                    <li><a href="<?php echo esc_url($topic['url']); ?>"><?php echo esc_html($topic['name']); ?> <span aria-hidden="true">↗</span></a></li>
                <?php endforeach; ?>
            </ul>
        </section>
    <?php endif; ?>

    <?php if ($posts_to_show) : ?>
        <section class="wpm-wrap wpm-section" aria-labelledby="wpm-guides">
            <h2 id="wpm-guides"><?php echo $is_kitchen ? 'Featured guides' : 'Latest guides'; ?></h2>
            <ul class="wpm-guides">
                <?php foreach ($posts_to_show as $guide) : ?>
                    <li>
                        <h3><a href="<?php echo esc_url(get_permalink($guide)); ?>"><?php echo esc_html(get_the_title($guide)); ?></a></h3>
                        <p><?php echo esc_html(wp_trim_words(wp_strip_all_tags(get_the_excerpt($guide)), 24)); ?></p>
                    </li>
                <?php endforeach; ?>
            </ul>
        </section>
    <?php endif; ?>

    <?php if (get_next_posts_page_link()) : ?>
        <div class="wpm-wrap wpm-section">
            <a class="wpm-button" href="<?php echo esc_url(get_next_posts_page_link()); ?>">More guides</a>
        </div>
    <?php endif; ?>
</main>
<?php get_footer(); ?>
