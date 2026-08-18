"use strict";

/*
 * SentinelDNS DNS Queries Monitor
 *
 * Responsibilities:
 * - Fetch authenticated DNS query records
 * - Display recent DNS activity
 * - Display cache/filter/upstream status
 * - Provide domain/status/cache filtering
 * - Refresh automatically
 *
 * Security:
 * - Uses same-origin browser credentials
 * - Never reads the authentication cookie
 * - Never stores JWTs
 * - Uses textContent for rendered values
 */

const QUERIES_API = "/api/queries/recent";
const QUERY_LIMIT = 50;
const REFRESH_INTERVAL = 5000;

let allQueries = [];
let refreshTimer = null;


// ==========================================================
// DOM HELPERS
// ==========================================================

function getElement(id) {
    return document.getElementById(id);
}


function setText(id, value) {
    const element = getElement(id);

    if (element) {
        element.textContent = String(value);
    }
}


// ==========================================================
// STATUS
// ==========================================================

function setQueryStatus(
    message,
    state = "",
) {
    const element = getElement(
        "query-status",
    );

    if (!element) {
        return;
    }

    element.textContent = message;

    element.classList.remove(
        "loading",
        "live",
        "error",
        "auth-required",
    );

    if (state) {
        element.classList.add(state);
    }
}


// ==========================================================
// LOAD QUERIES
// ==========================================================

async function loadQueries() {

    setQueryStatus(
        "Loading",
        "loading",
    );

    try {

        const response = await fetch(
            `${QUERIES_API}?limit=${QUERY_LIMIT}`,
            {
                method: "GET",

                credentials: "same-origin",

                headers: {
                    "Accept": "application/json",
                },

                cache: "no-store",
            },
        );


        // --------------------------------------------------
        // Authentication failure
        // --------------------------------------------------

        if (response.status === 401) {

            setQueryStatus(
                "Authentication required",
                "auth-required",
            );

            renderEmptyState(
                "Your session has expired. Please sign in again.",
            );

            /*
             * Do not redirect immediately.
             *
             * This makes the authentication problem visible
             * instead of silently reloading the page every
             * five seconds.
             */

            return;
        }


        // --------------------------------------------------
        // Other HTTP errors
        // --------------------------------------------------

        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`,
            );
        }


        // --------------------------------------------------
        // Parse API response
        // --------------------------------------------------

        const data = await response.json();


        if (
            !data
            || !Array.isArray(data.queries)
        ) {

            throw new Error(
                "Invalid queries API response.",
            );
        }


        // --------------------------------------------------
        // Store records
        // --------------------------------------------------

        allQueries = data.queries;


        // --------------------------------------------------
        // Update UI
        // --------------------------------------------------

        renderQueries();

        updateStatistics();

        updateLastUpdated();


        setQueryStatus(
            "LIVE",
            "live",
        );


    } catch (error) {

        console.error(
            "Failed to load DNS queries:",
            error,
        );

        setQueryStatus(
            "Error",
            "error",
        );

        renderEmptyState(
            "Unable to load DNS queries.",
        );
    }
}


// ==========================================================
// RENDER QUERIES
// ==========================================================

function renderQueries() {

    const tableBody = getElement(
        "query-table-body",
    );

    if (!tableBody) {
        return;
    }


    tableBody.replaceChildren();


    // ------------------------------------------------------
    // Search
    // ------------------------------------------------------

    const domainSearch = (
        getElement("query-search")?.value || ""
    )
        .trim()
        .toLowerCase();


    // ------------------------------------------------------
    // Status filter
    // ------------------------------------------------------

    const statusFilter = (
        getElement("status-filter")?.value || "ALL"
    );


    // ------------------------------------------------------
    // Cache filter
    // ------------------------------------------------------

    const cacheFilter = (
        getElement("cache-filter")?.value || "ALL"
    );


    // ------------------------------------------------------
    // Apply filters
    // ------------------------------------------------------

    const filteredQueries = allQueries.filter(
        (query) => {

            const domain = String(
                query.domain || "",
            ).toLowerCase();


            const domainMatches =
                !domainSearch
                || domain.includes(
                    domainSearch,
                );


            const statusMatches =
                statusFilter === "ALL"
                || query.status === statusFilter;


            const cacheMatches =
                cacheFilter === "ALL"
                || query.cache === cacheFilter;


            return (
                domainMatches
                && statusMatches
                && cacheMatches
            );
        },
    );


    // ------------------------------------------------------
    // Empty result
    // ------------------------------------------------------

    if (filteredQueries.length === 0) {

        renderEmptyState(
            allQueries.length === 0
                ? "No DNS queries recorded yet."
                : "No queries match the selected filters.",
        );

        return;
    }


    // ------------------------------------------------------
    // Render rows
    // ------------------------------------------------------

    for (
        const query
        of filteredQueries
    ) {

        const row = document.createElement(
            "tr",
        );


        addCell(
            row,
            query.domain,
        );


        addCell(
            row,
            query.query_type,
        );


        addStatusCell(
            row,
            query.status,
        );


        addStatusCell(
            row,
            query.cache,
        );


        addStatusCell(
            row,
            query.upstream,
        );


        addCell(
            row,
            query.rcode ?? "-",
        );


        addCell(
            row,
            formatLatency(
                query.latency_ms,
            ),
        );


        addCell(
            row,
            formatTime(
                query.timestamp,
            ),
        );


        tableBody.appendChild(
            row,
        );
    }
}


// ==========================================================
// EMPTY TABLE
// ==========================================================

function renderEmptyState(message) {

    const tableBody = getElement(
        "query-table-body",
    );

    if (!tableBody) {
        return;
    }


    tableBody.replaceChildren();


    const row = document.createElement(
        "tr",
    );


    const cell = document.createElement(
        "td",
    );


    cell.colSpan = 8;

    cell.className = "table-message";

    cell.textContent = message;


    row.appendChild(
        cell,
    );


    tableBody.appendChild(
        row,
    );
}


// ==========================================================
// TABLE CELLS
// ==========================================================

function addCell(
    row,
    value,
) {

    const cell = document.createElement(
        "td",
    );


    cell.textContent = (
        value === null
        || value === undefined
    )
        ? "-"
        : String(value);


    row.appendChild(
        cell,
    );
}


function addStatusCell(
    row,
    value,
) {

    const cell = document.createElement(
        "td",
    );


    const badge = document.createElement(
        "span",
    );


    badge.textContent = (
        value === null
        || value === undefined
    )
        ? "-"
        : String(value);


    badge.className = (
        "query-status-value"
    );


    if (value) {

        badge.classList.add(
            String(value)
                .toLowerCase()
                .replaceAll(
                    "_",
                    "-",
                ),
        );
    }


    cell.appendChild(
        badge,
    );

    row.appendChild(
        cell,
    );
}


// ==========================================================
// FORMATTERS
// ==========================================================

function formatLatency(
    latency,
) {

    const numericLatency = Number(
        latency,
    );


    if (
        !Number.isFinite(
            numericLatency,
        )
    ) {

        return "-";
    }


    return (
        `${numericLatency.toFixed(1)} ms`
    );
}


function formatTime(
    timestamp,
) {

    if (!timestamp) {
        return "-";
    }


    const date = new Date(
        timestamp,
    );


    if (
        Number.isNaN(
            date.getTime(),
        )
    ) {

        return "-";
    }


    return date.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        },
    );
}


// ==========================================================
// STATISTICS
// ==========================================================

function updateStatistics() {

    // Total
    setText(
        "query-count",
        allQueries.length,
    );


    // Allowed
    setText(
        "allowed-count",
        allQueries.filter(
            (query) =>
                query.status === "ALLOWED",
        ).length,
    );


    // Blocked
    setText(
        "blocked-count",
        allQueries.filter(
            (query) =>
                query.status === "BLOCKED",
        ).length,
    );


    // Cache HIT
    setText(
        "cache-hit-count",
        allQueries.filter(
            (query) =>
                query.cache === "HIT",
        ).length,
    );


    // Cache MISS
    setText(
        "cache-miss-count",
        allQueries.filter(
            (query) =>
                query.cache === "MISS",
        ).length,
    );
}


// ==========================================================
// LAST UPDATED
// ==========================================================

function updateLastUpdated() {

    const element = getElement(
        "last-updated",
    );


    if (!element) {
        return;
    }


    element.textContent =
        `Updated ${new Date().toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
            },
        )}`;
}


// ==========================================================
// FILTERS
// ==========================================================

function setupFilters() {

    const search = getElement(
        "query-search",
    );


    const status = getElement(
        "status-filter",
    );


    const cache = getElement(
        "cache-filter",
    );


    if (search) {

        search.addEventListener(
            "input",
            renderQueries,
        );
    }


    if (status) {

        status.addEventListener(
            "change",
            renderQueries,
        );
    }


    if (cache) {

        cache.addEventListener(
            "change",
            renderQueries,
        );
    }
}


// ==========================================================
// MANUAL REFRESH
// ==========================================================

function setupRefreshButton() {

    const button = getElement(
        "refresh-queries",
    );


    if (!button) {
        return;
    }


    button.addEventListener(
        "click",
        async () => {

            button.disabled = true;

            try {

                await loadQueries();

            } finally {

                button.disabled = false;
            }
        },
    );
}


// ==========================================================
// INITIALIZATION
// ==========================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupFilters();

        setupRefreshButton();

        loadQueries();


        /*
         * Automatic refresh every five seconds.
         */

        refreshTimer = setInterval(
            loadQueries,
            REFRESH_INTERVAL,
        );
    },
);