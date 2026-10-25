/*
 * Table filtering, enhanced.
 *
 * Every table works with this file blocked: the toolbar is a GET form with an Apply button, the
 * sorts and the pages are links, and the per-column filter row is opened by a link that sets a
 * query value. Nothing here adds a capability. It removes a click.
 *
 * What it adds: typing settles and submits on its own, a select submits when it changes, and
 * the caret lands where it was so a filtered table can be typed into continuously. The server
 * remains the only thing that decides what matches, which is why a stale or half-typed term can
 * never show the wrong rows — it can only show rows for a term that was true a moment ago.
 */

"use strict";

/** How long typing has to stop before the form submits. */
const SETTLE_MS = 350;

/**
 * Remembers which field the person was typing in, and puts the caret back after the reload.
 *
 * Without this, a submit on every keystroke-settle is unusable: focus returns to the top of the
 * document and the next character goes nowhere. sessionStorage rather than a query value,
 * because where someone's caret is has no business in a shareable URL.
 */
const FOCUS_KEY = "keystead.table.focus";

function restoreFocus() {
    let saved = null;

    try {
        saved = window.sessionStorage.getItem(FOCUS_KEY);
        window.sessionStorage.removeItem(FOCUS_KEY);
    } catch {
        // Private mode, or storage refused. The page is still correct, just less convenient.
        return;
    }

    if (!saved) {
        return;
    }

    const field = document.querySelector(`[name="${CSS.escape(saved)}"]`);

    if (!(field instanceof HTMLInputElement)) {
        return;
    }

    field.focus();

    // The caret goes to the end rather than position zero, which is where focus() leaves it.
    const end = field.value.length;

    try {
        field.setSelectionRange(end, end);
    } catch {
        // Not every input type supports a selection range. Focus alone is the useful part.
    }
}

function rememberFocus(name) {
    try {
        window.sessionStorage.setItem(FOCUS_KEY, name);
    } catch {
        // See restoreFocus: a convenience, never a requirement.
    }
}

function initTableFilter(form) {
    let timer = null;

    function submit(field) {
        if (field?.name) {
            rememberFocus(field.name);
        }

        // Any page number in the URL belongs to the previous filter. Submitting without it
        // returns to page one, which is the only page guaranteed to exist for a new filter.
        form.submit();
    }

    // The fields in the header row belong to this form through their form attribute, so they
    // are not descendants of it. form.elements covers both, which querySelectorAll would not.
    for (const field of form.elements) {
        if (field.dataset?.tableSubmit !== undefined) {
            field.addEventListener("change", () => submit(field));
            continue;
        }

        if (!(field instanceof HTMLInputElement)) {
            continue;
        }

        if (field.type !== "search" && field.type !== "text") {
            continue;
        }

        field.addEventListener("input", () => {
            window.clearTimeout(timer);
            timer = window.setTimeout(() => submit(field), SETTLE_MS);
        });

        // Enter submits anyway; cancelling the timer stops a second submit landing on top of
        // the first and turning one navigation into two history entries.
        field.addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                window.clearTimeout(timer);
            }

            // Escape clears the field and shows everything again, which is what the key does
            // in every other search box people use.
            if (event.key === "Escape" && field.value !== "") {
                event.preventDefault();
                field.value = "";
                window.clearTimeout(timer);
                submit(field);
            }
        });
    }
}

/**
 * Makes a whole row follow the link inside it.
 *
 * The anchor is real and is what a keyboard and a screen reader use; this only widens the
 * target to the rest of the row for a pointer. A click that lands on a button, a link or a
 * form control inside the row is left alone, and so is a click that is really a text
 * selection — dragging to copy an address out of a table should not navigate.
 */
function initRowLinks() {
    for (const row of document.querySelectorAll("tr[data-row-url]")) {
        row.classList.add("is-selectable");

        row.addEventListener("click", (event) => {
            if (event.target.closest("a, button, input, select, textarea, label")) {
                return;
            }

            if ((window.getSelection()?.toString() ?? "") !== "") {
                return;
            }

            window.location.assign(row.dataset.rowUrl);
        });
    }
}

function init() {
    for (const form of document.querySelectorAll("[data-table-filter]")) {
        initTableFilter(form);
    }

    initRowLinks();
    restoreFocus();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
    init();
}
