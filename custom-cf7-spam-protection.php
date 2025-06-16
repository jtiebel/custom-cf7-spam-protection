<?php
/*
Plugin Name: CF7 Advanced Honeypot Anti-Spam V4 PRO
Description: Next-Gen Anti-Spam Plugin für Contact Form 7 mit Honeypot, Heuristik, Logging, URL-Detection, Text-Checks, Session und Fail-Safe.
Version: 4.0
Author: Jakob Tiebel - Native Health Consulting
*/

if (!defined('ABSPATH')) exit;

class CF7_Advanced_Honeypot_V4 {

    private $option_name = 'cf7_advanced_honeypot_v4_options';
    private $default_options = [
        'score_threshold' => 20,
        'log_limit' => 100
    ];

    public function __construct() {
        add_filter('wpcf7_form_elements', [$this, 'inject_honeypot']);
        add_filter('wpcf7_validate', [$this, 'validate_submission'], 10, 2);
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('init', [$this, 'start_session'], 1);
    }

    public function start_session() {
        if (!session_id()) {
            session_start();
        }
    }

    public function get_options() {
        return wp_parse_args(get_option($this->option_name, []), $this->default_options);
    }

    public function inject_honeypot($form) {
        // Session Token erzeugen
        $token = bin2hex(random_bytes(16));
        $_SESSION['cf7_honeypot_token'] = $token;

        $honeypot = '<div style="position:absolute; left:-9999px; top:auto; width:1px; height:1px; overflow:hidden;">';
        $honeypot .= '<input type="text" id="contact_time" name="contact_time" autocomplete="off" tabindex="-1">';
        $honeypot .= '<input type="hidden" name="honeypot_focused" id="honeypot_focused" value="0">';
        $honeypot .= '<input type="email" id="email_confirm" name="email_confirm" autocomplete="off" tabindex="-1">';
        $honeypot .= '<input type="hidden" name="form_start_time" id="form_start_time">';
        $honeypot .= '<input type="hidden" name="key_pressed" id="key_pressed" value="0">';
        $honeypot .= '<input type="hidden" name="mouse_moved" id="mouse_moved" value="0">';
        $honeypot .= '<input type="hidden" name="honeypot_token" value="'.$token.'">';
        $honeypot .= '</div>';

        $honeypot .= '<script>
            document.addEventListener("DOMContentLoaded", function() {
                const formStartTime = Date.now();
                document.getElementById("form_start_time").value = formStartTime;

                document.getElementById("contact_time").addEventListener("focus", function() {
                    document.getElementById("honeypot_focused").value = "1";
                });

                document.addEventListener("keydown", function() {
                    document.getElementById("key_pressed").value = "1";
                });

                document.addEventListener("mousemove", function() {
                    document.getElementById("mouse_moved").value = "1";
                });
            });
        </script>';

        return $form . $honeypot;
    }

    public function validate_submission($result, $tags) {
        $score = 0;
        $log = [];

        // Session Check
        if (empty($_POST['honeypot_token']) || empty($_SESSION['cf7_honeypot_token']) || $_POST['honeypot_token'] !== $_SESSION['cf7_honeypot_token']) {
            $score += 15; $log[] = "Session mismatch";
        }

        // Honeypot
        if (!empty($_POST['contact_time'])) { $score += 10; $log[] = "Honeypot ausgefüllt"; }
        if (!empty($_POST['honeypot_focused']) && $_POST['honeypot_focused'] == "1") { $score += 5; $log[] = "Honeypot fokussiert"; }
        if (!empty($_POST['email_confirm'])) { $score += 10; $log[] = "Email Confirm ausgefüllt"; }

        // Timing
        if (!empty($_POST['form_start_time'])) {
            $start = intval($_POST['form_start_time']);
            $now = round(microtime(true) * 1000);
            $duration = ($now - $start) / 1000;
            if ($duration < 1) { $score += 15; $log[] = "unter 1s"; }
            elseif ($duration < 3) { $score += 5; $log[] = "unter 3s"; }
        }

        // Interaktion
        if (empty($_POST['key_pressed']) || $_POST['key_pressed'] == "0") { $score += 10; $log[] = "keine Tastatureingabe"; }
        if (empty($_POST['mouse_moved']) || $_POST['mouse_moved'] == "0") { $score += 5; $log[] = "keine Mausbewegung"; }

        // User Agent
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (empty($ua) || stripos($ua, 'Headless') !== false || stripos($ua, 'Python') !== false || stripos($ua, 'curl') !== false) {
            $score += 10; $log[] = "User Agent verdächtig";
        }

        // Keyword Heuristik
        $spam_words = ['bitcoin','loan','seo','escort','casino','viagra','porn','sex','investment','crypto'];
        foreach ($_POST as $val) {
            foreach ($spam_words as $word) {
                if (stripos($val, $word) !== false) { $score += 15; $log[] = "Keyword: {$word}"; break 2; }
            }
        }

        // URL Detection
        foreach ($_POST as $val) {
            if (preg_match('/https?:\/\//i', $val)) {
                $score += 15; $log[] = "URL erkannt";
                break;
            }
        }

        // Textlänge Check (Short/Long Text)
        foreach ($_POST as $val) {
            if (is_string($val)) {
                $word_count = str_word_count($val);
                if ($word_count < 3) { $score += 5; $log[] = "sehr kurzer Text"; }
                if ($word_count > 300) { $score += 5; $log[] = "sehr langer Text"; }
            }
        }

        $options = $this->get_options();

        // Fail-Safe Mode
        if ($score >= intval($options['score_threshold'])) {
            $result->invalidate('', "Spam-Verdacht. Ihre Nachricht wurde nicht übermittelt.");
            $this->log_event("BLOCKIERT: {$score} | ".implode(", ", $log));
        } elseif ($score >= intval($options['score_threshold']) - 5) {
            $this->log_event("WARNUNG: {$score} | ".implode(", ", $log));
            // Fail-Safe: Nachricht durchlassen aber als Warnung loggen
        } else {
            $this->log_event("OK: {$score} | ".implode(", ", $log));
        }

        return $result;
    }

    private function log_event($entry) {
        $log = get_option('cf7_advanced_honeypot_v4_log', []);
        array_unshift($log, date('Y-m-d H:i:s').' | '.$entry);
        $limit = $this->get_options()['log_limit'];
        if (count($log) > $limit) { $log = array_slice($log, 0, $limit); }
        update_option('cf7_advanced_honeypot_v4_log', $log);
    }

    public function admin_menu() {
        add_options_page('CF7 Honeypot V4', 'CF7 Honeypot V4', 'manage_options', 'cf7-honeypot-v4', [$this, 'settings_page']);
    }

    public function register_settings() {
        register_setting('cf7_honeypot_v4_settings', $this->option_name);
    }

    public function settings_page() {
        $options = $this->get_options();
        ?>
        <div class="wrap">
            <h1>CF7 Advanced Honeypot V4</h1>
            <form method="post" action="options.php">
                <?php settings_fields('cf7_honeypot_v4_settings'); ?>
                <table class="form-table">
                    <tr>
                        <th>Score Schwelle</th>
                        <td><input type="number" name="<?php echo $this->option_name; ?>[score_threshold]" value="<?php echo esc_attr($options['score_threshold']); ?>"></td>
                    </tr>
                    <tr>
                        <th>Log Limit (Einträge)</th>
                        <td><input type="number" name="<?php echo $this->option_name; ?>[log_limit]" value="<?php echo esc_attr($options['log_limit']); ?>"></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <h2>Aktuelle Logs:</h2>
            <pre style="background:#eee;padding:10px;max-height:400px;overflow:auto;">
            <?php
            $log = get_option('cf7_advanced_honeypot_v4_log', []);
            foreach ($log as $entry) { echo esc_html($entry)."\n"; }
            ?>
            </pre>
        </div>
        <?php
    }
}

new CF7_Advanced_Honeypot_V4();
