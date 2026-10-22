/*
 * Keystead application shell behaviour.
 *
 * Progressive enhancement only: every page works with this file blocked. There are no inline
 * handlers anywhere in the markup, because the Content Security Policy forbids inline script
 * and we would rather the policy be strict than convenient.
 *
 * Behaviour is wired by data-action attributes rather than by element id, so markup can move
 * without breaking the script.
 */

"use strict";

/** Opens and closes the sidebar drawer on narrow viewports. */
function initSidebarToggle() {
    const toggle = document.querySelector('[data-action="toggle-sidebar"]');
    const sidebar = document.getElementById("sidebar");

    if (!toggle || !sidebar) {
        return;
    }

    toggle.addEventListener("click", () => {
        const open = sidebar.dataset.open === "true";
        sidebar.dataset.open = String(!open);
        toggle.setAttribute("aria-expanded", String(!open));
    });

    // Escape closes the drawer, which is what a keyboard user will reach for first.
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && sidebar.dataset.open === "true") {
            sidebar.dataset.open = "false";
            toggle.setAttribute("aria-expanded", "false");
            toggle.focus();
        }
    });
}

/**
 * Ctrl+K / Cmd+K focuses the global search box.
 *
 * The full command palette arrives with the rest of the search UI; until then the shortcut
 * does the useful half of the job rather than nothing.
 */
function initSearchShortcut() {
    const search = document.getElementById("global-search");

    if (!search) {
        return;
    }

    document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
            event.preventDefault();
            search.focus();
            search.select();
        }
    });
}

/**
 * Copies a value to the clipboard and clears it again after a delay.
 *
 * A secret left on the clipboard is a secret in every application the user pastes into next,
 * so the clipboard is overwritten rather than left holding it indefinitely.
 */
function initCopyButtons() {
    for (const button of document.querySelectorAll('[data-action="copy"]')) {
        button.addEventListener("click", async () => {
            const target = document.getElementById(button.dataset.copyTarget ?? "");
            const value = target?.textContent ?? "";

            if (!value) {
                return;
            }

            try {
                await navigator.clipboard.writeText(value);
                announce(button, "Copied");

                window.setTimeout(async () => {
                    try {
                        // Overwrite rather than clear: an empty clipboard is itself a hint
                        // that something sensitive was just there.
                        await navigator.clipboard.writeText(" ");
                    } catch {
                        // The tab lost focus, so the clipboard is not ours to touch any more.
                    }
                }, 30_000);
            } catch {
                announce(button, "Copy failed");
            }
        });
    }
}

/** Briefly replaces a button's label, and announces the change to assistive technology. */
function announce(button, message) {
    const original = button.getAttribute("data-label") ?? button.textContent ?? "";
    button.setAttribute("data-label", original);
    button.textContent = message;
    button.setAttribute("aria-live", "polite");

    window.setTimeout(() => {
        button.textContent = original;
    }, 1_800);
}

function init() {
    initSidebarToggle();
    initSearchShortcut();
    initCopyButtons();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
    init();
}
