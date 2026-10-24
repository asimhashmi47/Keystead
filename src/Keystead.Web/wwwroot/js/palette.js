/*
 * The command palette.
 *
 * Ctrl+K (or Cmd+K) opens a dialog, typing searches vault and secret names, and the results
 * are keyboard navigable. Built on <dialog>, so focus trapping, Escape to close and the
 * backdrop all come from the platform rather than from a hand-rolled modal that gets the
 * accessibility details almost right.
 *
 * Progressive enhancement: without this file, Ctrl+K does nothing and the search box in the
 * top bar still works as an ordinary form.
 */

"use strict";

const DEBOUNCE_MS = 150;
const MIN_QUERY = 1;

function initPalette() {
    const dialog = document.getElementById("palette");

    if (!dialog || typeof dialog.showModal !== "function") {
        return;
    }

    const input = dialog.querySelector("[data-palette-input]");
    const list = dialog.querySelector("[data-palette-results]");
    const status = dialog.querySelector("[data-palette-status]");

    if (!input || !list || !status) {
        return;
    }

    let timer = null;
    let controller = null;
    let active = -1;

    function open() {
        if (dialog.open) {
            return;
        }

        input.value = "";
        list.replaceChildren();
        status.textContent = "Type to search vault and secret names.";
        active = -1;
        dialog.showModal();
        input.focus();
    }

    function rows() {
        return Array.from(list.querySelectorAll("a"));
    }

    function highlight(next) {
        const items = rows();

        if (items.length === 0) {
            return;
        }

        // Wraps at both ends, which is what anyone who has used a palette expects.
        active = (next + items.length) % items.length;

        items.forEach((item, index) => {
            const isActive = index === active;
            item.setAttribute("aria-selected", String(isActive));
            item.classList.toggle("palette__hit--active", isActive);

            if (isActive) {
                item.scrollIntoView({ block: "nearest" });
            }
        });
    }

    function render(hits) {
        list.replaceChildren();
        active = -1;

        if (hits.length === 0) {
            status.textContent = "Nothing matched.";
            return;
        }

        // One announcement rather than one per row, so a screen reader is told the count
        // instead of reading the whole list on every keystroke.
        status.textContent = `${hits.length} result${hits.length === 1 ? "" : "s"}.`;

        for (const hit of hits) {
            const item = document.createElement("a");
            item.className = "palette__hit";
            item.href = hit.url;
            item.setAttribute("role", "option");
            item.setAttribute("aria-selected", "false");

            const kind = document.createElement("span");
            kind.className = "badge badge--neutral";
            kind.textContent = hit.kind;

            const title = document.createElement("span");
            title.className = "palette__hit-title";

            // textContent, never innerHTML. The names come from the database and are shown
            // back to the user; building this with markup would be an injection route.
            title.textContent = hit.title;

            const subtitle = document.createElement("span");
            subtitle.className = "palette__hit-subtitle";
            subtitle.textContent = hit.subtitle;

            item.append(kind, title, subtitle);
            list.append(item);
        }

        highlight(0);
    }

    async function search(query) {
        controller?.abort();
        controller = new AbortController();

        try {
            const response = await fetch(
                `/search?handler=Query&q=${encodeURIComponent(query)}`,
                {
                    headers: { Accept: "application/json" },
                    credentials: "same-origin",
                    cache: "no-store",
                    signal: controller.signal,
                });

            if (!response.ok) {
                status.textContent = "Search failed.";
                return;
            }

            render(await response.json());
        } catch (error) {
            if (error.name !== "AbortError") {
                status.textContent = "Search failed.";
            }
        }
    }

    document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
            event.preventDefault();
            open();
        }
    });

    for (const trigger of document.querySelectorAll('[data-action="open-palette"]')) {
        trigger.addEventListener("click", open);
    }

    input.addEventListener("input", () => {
        window.clearTimeout(timer);
        const query = input.value.trim();

        if (query.length < MIN_QUERY) {
            list.replaceChildren();
            status.textContent = "Type to search vault and secret names.";
            return;
        }

        // Debounced so that typing a name does not fire a request per character.
        timer = window.setTimeout(() => search(query), DEBOUNCE_MS);
    });

    input.addEventListener("keydown", (event) => {
        if (event.key === "ArrowDown") {
            event.preventDefault();
            highlight(active + 1);
        } else if (event.key === "ArrowUp") {
            event.preventDefault();
            highlight(active - 1);
        } else if (event.key === "Enter") {
            const items = rows();

            if (active >= 0 && items[active]) {
                event.preventDefault();
                window.location.assign(items[active].href);
            }
        }
    });

    dialog.addEventListener("close", () => {
        controller?.abort();
        window.clearTimeout(timer);
        list.replaceChildren();
    });

    // Clicking the backdrop closes it. <dialog> reports a click on itself rather than on its
    // content when the backdrop is hit.
    dialog.addEventListener("click", (event) => {
        if (event.target === dialog) {
            dialog.close();
        }
    });
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPalette, { once: true });
} else {
    initPalette();
}
