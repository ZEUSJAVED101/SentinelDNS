"use strict";

(function () {

    const body = document.getElementById(
        "security-events-body"
    );

    const status = document.getElementById(
        "event-status"
    );

    if (!body) {
        return;
    }

    function escapeHtml(value) {

        const div = document.createElement(
            "div"
        );

        div.textContent =
            value === null ||
            value === undefined
                ? "—"
                : String(value);

        return div.innerHTML;
    }


    function renderEvents(events) {

        if (!Array.isArray(events) || events.length === 0) {

            body.innerHTML = `
                <tr id="empty-events">
                    <td
                        colspan="5"
                        class="empty-state"
                    >
                        No security events recorded yet.
                    </td>
                </tr>
            `;

            return;
        }


        body.innerHTML = events.map(function (event) {

            return `
                <tr>

                    <td>
                        ${escapeHtml(event.timestamp)}
                    </td>

                    <td>
                        ${escapeHtml(event.event_type)}
                    </td>

                    <td>
                        ${escapeHtml(event.filter_name)}
                    </td>

                    <td>
                        <span class="event-action">
                            ${escapeHtml(event.action)}
                        </span>
                    </td>

                    <td>
                        ${escapeHtml(event.reason)}
                    </td>

                </tr>
            `;

        }).join("");
    }


    async function refreshEvents() {

        try {

            const response = await fetch(
                "/api/security-events",
                {
                    method: "GET",
                    credentials: "same-origin",
                    cache: "no-store",
                    headers: {
                        "Accept": "application/json"
                    }
                }
            );

            if (!response.ok) {
                throw new Error(
                    "HTTP " + response.status
                );
            }

            const data =
                await response.json();

            renderEvents(
                data.events || []
            );

            if (status) {

                status.textContent = "LIVE";
                status.dataset.state = "live";
            }

        } catch (error) {

            console.error(
                "Security event refresh failed:",
                error
            );

            if (status) {

                status.textContent = "OFFLINE";
                status.dataset.state = "error";
            }
        }
    }


    refreshEvents();

    window.setInterval(
        refreshEvents,
        2000
    );

})();