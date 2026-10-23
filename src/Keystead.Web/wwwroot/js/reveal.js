/*
 * The secret reveal flow.
 *
 * Fetches the value by POST with an antiforgery token, shows it, and hides it again after the
 * window the server specifies. Nothing here caches the value: it lives in one local variable
 * and in the DOM text node, both cleared on hide.
 *
 * Progressive enhancement, with a caveat worth stating: without this script the value cannot be
 * revealed at all. That is the right failure direction for a secrets manager. Every other
 * action on the page, including storing a new version and rolling back, works without it.
 */

"use strict";

const MASK = "•".repeat(24);

function initReveal() {
    const button = document.querySelector("[data-reveal]");
    const output = document.querySelector("[data-reveal-output]");
    const status = document.querySelector("[data-reveal-status]");
    const countdown = document.querySelector("[data-reveal-countdown]");
    const copyButton = document.querySelector("[data-reveal-copy]");

    if (!button || !output) {
        return;
    }

    let hideTimer = null;
    let tickTimer = null;

    function hide() {
        window.clearTimeout(hideTimer);
        window.clearInterval(tickTimer);

        output.textContent = MASK;
        button.disabled = false;
        button.textContent = "Reveal value";

        if (copyButton) {
            copyButton.hidden = true;
        }

        if (countdown) {
            countdown.textContent = "";
        }

        if (status) {
            status.textContent =
                "Hidden again. Revealing is recorded in the audit log.";
        }
    }

    function startCountdown(seconds) {
        let remaining = seconds;

        if (countdown) {
            countdown.textContent = `Hiding in ${remaining}s`;
        }

        tickTimer = window.setInterval(() => {
            remaining -= 1;

            if (countdown) {
                countdown.textContent = remaining > 0 ? `Hiding in ${remaining}s` : "";
            }

            if (remaining <= 0) {
                window.clearInterval(tickTimer);
            }
        }, 1000);

        hideTimer = window.setTimeout(hide, seconds * 1000);
    }

    button.addEventListener("click", async () => {
        button.disabled = true;
        button.textContent = "Revealing...";

        try {
            const response = await fetch(button.dataset.revealUrl, {
                method: "POST",
                headers: {
                    // The header name configured on AntiforgeryOptions. Sent as a header rather
                    // than a form field because this is a fetch, not a form post.
                    "X-Keystead-CSRF": button.dataset.csrf ?? "",
                    "Accept": "application/json",
                },

                // Same-origin only. The policy forbids cross-origin requests anyway, but
                // saying so here means a misconfigured policy does not silently widen this.
                credentials: "same-origin",
                cache: "no-store",
            });

            const payload = await response.json().catch(() => ({}));

            if (response.status === 403 && payload.stepUpRequired) {
                // Answerable, so send them to confirm rather than showing a refusal.
                if (status) {
                    status.textContent = payload.message ?? "Confirm your identity to continue.";
                }

                window.location.assign(payload.stepUpUrl);
                return;
            }

            if (!response.ok) {
                if (status) {
                    status.textContent = payload.message ?? "That value could not be revealed.";
                }

                button.disabled = false;
                button.textContent = "Reveal value";
                return;
            }

            output.textContent = payload.value ?? "";
            button.textContent = "Hide value";
            button.disabled = false;

            if (copyButton) {
                copyButton.hidden = false;
            }

            if (status) {
                status.textContent = `Showing version ${payload.version}. This read has been recorded.`;
            }

            startCountdown(payload.autoHideSeconds ?? 30);

            // While revealed, the button hides instead of re-fetching.
            button.addEventListener("click", hide, { once: true });
        } catch {
            if (status) {
                status.textContent = "The request failed. Nothing was revealed.";
            }

            button.disabled = false;
            button.textContent = "Reveal value";
        }
    }, { once: true });

    // Leaving the page clears the value from the DOM rather than leaving it in a cached
    // rendering of the document.
    window.addEventListener("pagehide", hide);
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initReveal, { once: true });
} else {
    initReveal();
}
