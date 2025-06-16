<?php
/*
Plugin Name: CF7 Advanced Honeypot Anti-Spam V2
Description: Erweiterter Honeypot-Schutz für Contact Form 7 mit Timing, Interaktion, Scoring, Bot-Heuristik und Keyword-Prüfung.
Version: 2.0
Author: Jakob Tiebel - Native Health Consulting
*/

if (!defined('ABSPATH')) exit;

// Inject Honeypot + Detection Fields in alle CF7-Formulare
add_filter('wpcf7_form_elements', 'cf7_advanced_honeypot_v2_inject');

function cf7_advanced_honeypot_v2_inject($form) {
    $honeypot = '<div style="position:absolute; left:-9999px; top:auto; width:1px; height:1px; overflow:hidden;">';
    $honeypot .= '<label for="contact_time">Anfragezeitpunkt</label>';
    $honeypot .= '<input type="text" id="contact_time" name="contact_time" autocomplete="off" tabindex="-1">';
    $honeypot .= '<input type="hidden" name="honeypot_focused" id="honeypot_focused" value="0">';
    $honeypot .= '<label for="email_confirm">Email Bestätigung</label>';
    $honeypot .= '<input type="email" id="email_confirm" name="email_confirm" autocomplete="off" tabindex="-1">';
    $honeypot .= '<input type="hidden" name="form_start_time" id="form_start_time">';
    $honeypot .= '<input type="hidden" name="key_pressed" id="key_pressed" value="0">';
    $honeypot .= '<input type="hidden" name="mouse_moved" id="mouse_moved" value="0">';
    $honeypot .= '</div>';

    $honeypot .= '<script>
        document.addEventListener("DOMContentLoaded", function() {
            const formStartTime = Date.now();
            document.getElementById("form_start_time").value = formStartTime;

            var honeypot = document.getElementById("contact_time");
            honeypot.addEventListener("focus", function() {
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

// Validierung bei Absenden
add_filter('wpcf7_validate', 'cf7_advanced_honeypot_v2_validate', 10, 2);

function cf7_advanced_honeypot_v2_validate($result, $tags) {
    $score = 0;
    $log = [];

    // Honeypot ausgefüllt?
    if (!empty($_POST['contact_time'])) {
        $score += 10;
        $log[] = "Honeypot ausgefüllt";
    }

    // Honeypot fokussiert?
    if (!empty($_POST['honeypot_focused']) && $_POST['honeypot_focused'] == "1") {
        $score += 5;
        $log[] = "Honeypot fokussiert";
    }

    // Email Confirmation Trap
    if (!empty($_POST['email_confirm'])) {
        $score += 10;
        $log[] = "Email Confirm Feld ausgefüllt";
    }

    // Zeitmessung
    if (!empty($_POST['form_start_time'])) {
        $start_time = intval($_POST['form_start_time']);
        $now = round(microtime(true) * 1000);
        $duration = ($now - $start_time) / 1000;

        if ($duration > 0 && $duration < 1) {
            $score += 15;
            $log[] = "Formular unter 1 Sek ausgefüllt";
        } elseif ($duration < 3) {
            $score += 5;
            $log[] = "Formular unter 3 Sek ausgefüllt";
        }
    }

    // Keine Tastaturbetätigung?
    if (empty($_POST['key_pressed']) || $_POST['key_pressed'] == "0") {
        $score += 10;
        $log[] = "Keine Tastatureingabe erkannt";
    }

    // Keine Mausbewegung?
    if (empty($_POST['mouse_moved']) || $_POST['mouse_moved'] == "0") {
        $score += 5;
        $log[] = "Keine Mausbewegung erkannt";
    }

    // User-Agent prüfen
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (empty($user_agent) || stripos($user_agent, 'Headless') !== false || stripos($user_agent, 'Python') !== false || stripos($user_agent, 'curl') !== false) {
        $score += 10;
        $log[] = "User-Agent verdächtig";
    }

    // Content Heuristik (Spam Keywords prüfen)
    $spam_keywords = ['bitcoin', 'loan', 'seo', 'escort', 'casino', 'viagra', 'porn', 'sex', 'click here', 'investment', 'crypto'];
    foreach ($_POST as $field => $value) {
        foreach ($spam_keywords as $keyword) {
            if (stripos($value, $keyword) !== false) {
                $score += 15;
                $log[] = "Spamwort erkannt: {$keyword}";
                break 2; // nur erster Treffer reicht
            }
        }
    }

    // Entscheidung anhand Score
    if ($score >= 15) {
        $result->invalidate('', "Spam-Verdacht. Ihre Nachricht wurde nicht übermittelt.");
        error_log("SPAM BLOCKIERT: Score {$score} | " . implode(", ", $log));
    } else {
        error_log("Formular OK: Score {$score} | " . implode(", ", $log));
    }

    return $result;
}
