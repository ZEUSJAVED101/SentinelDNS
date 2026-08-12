/*
 * SentinelDNS Dashboard
 *
 * API:
 *   GET /api/dashboard/
 *
 * Security:
 * - Same-origin requests only
 * - No token storage in localStorage/sessionStorage
 * - Runtime values written with textContent
 * - No innerHTML for API data
 * - No sensitive data logged
 * - Bounded polling
 */

"use strict";

const DASHBOARD_API = "/api/dashboard/";
const REFRESH_INTERVAL_MS = 5000;
const MAX_HISTORY_POINTS = 60;

const state = {
    timer: null,
    refreshing: false,
    initialized: false,
};


/* ==========================================================
   DOM HELPERS
   ========================================================== */

function getElement(id) {
    return document.getElementById(id);
}


function setText(id, value) {
    const element = getElement(id);

    if (element) {
        element.textContent = String(value);
    }
}


/* ==========================================================
   FORMATTING
   ========================================================== */

function formatNumber(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return "0";
    }

    return Math.max(
        0,
        Math.trunc(number),
    ).toLocaleString();
}


function formatPercentage(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return "0.0%";
    }

    const bounded = Math.max(
        0,
        Math.min(1, number),
    );

    return `${(bounded * 100).toFixed(1)}%`;
}


function formatLatency(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return "0 ms";
    }

    return `${Math.max(0, number).toFixed(1)} ms`;
}


/* ==========================================================
   API
   ========================================================== */

async function fetchDashboard() {
    const response = await fetch(
        DASHBOARD_API,
        {
            method: "GET",

            credentials: "same-origin",

            headers: {
                "Accept": "application/json",
            },

            cache: "no-store",
        },
    );

    if (response.status === 401) {
        throw new Error(
            "AUTHENTICATION_REQUIRED",
        );
    }

    if (response.status === 403) {
        throw new Error(
            "ACCESS_DENIED",
        );
    }

    if (!response.ok) {
        throw new Error(
            "DASHBOARD_API_ERROR",
        );
    }

    const contentType = (
        response.headers.get(
            "content-type",
        ) || ""
    ).toLowerCase();

    if (
        !contentType.includes(
            "application/json",
        )
    ) {
        throw new Error(
            "INVALID_API_RESPONSE",
        );
    }

    const data = await response.json();

    if (
        !data ||
        typeof data !== "object" ||
        !data.metrics ||
        typeof data.metrics !== "object"
    ) {
        throw new Error(
            "INVALID_DASHBOARD_DATA",
        );
    }

    return data;
}


/* ==========================================================
   CONNECTION STATUS
   ========================================================== */

function setConnectionStatus(
    connected,
    message,
) {
    const element = getElement(
        "dashboard-status",
    );

    if (!element) {
        return;
    }

    element.textContent = message;

    element.dataset.connected = (
        connected
        ? "true"
        : "false"
    );
}


/* ==========================================================
   METRICS
   ========================================================== */

function updateMetrics(metrics) {
    if (
        !metrics ||
        typeof metrics !== "object"
    ) {
        return;
    }

    setText(
        "total-queries",
        formatNumber(
            metrics.total_queries,
        ),
    );

    setText(
        "blocked-queries",
        formatNumber(
            metrics.blocked_queries,
        ),
    );

    setText(
        "cache-hits",
        formatNumber(
            metrics.cache_hits,
        ),
    );

    setText(
        "allowed-queries",
        formatNumber(
            metrics.allowed_queries,
        ),
    );

    setText(
        "upstream-success",
        formatNumber(
            metrics.upstream_success,
        ),
    );

    setText(
        "upstream-failures",
        formatNumber(
            metrics.upstream_failures,
        ),
    );

    setText(
        "nxdomain-count",
        formatNumber(
            metrics.nxdomain,
        ),
    );

    setText(
        "servfail-count",
        formatNumber(
            metrics.servfail,
        ),
    );

    setText(
        "formerr-count",
        formatNumber(
            metrics.formerr,
        ),
    );

    setText(
        "other-rcodes",
        formatNumber(
            metrics.other_rcodes,
        ),
    );

    const queryRate = Number(
        metrics.query_rate,
    );

    setText(
        "query-rate",
        Number.isFinite(queryRate)
            ? `${queryRate.toFixed(2)} q/s`
            : "0.00 q/s",
    );

    setText(
        "average-latency",
        formatLatency(
            metrics.average_latency_ms,
        ),
    );

    setText(
        "max-latency",
        formatLatency(
            metrics.max_latency_ms,
        ),
    );
}


/* ==========================================================
   CACHE
   ========================================================== */

function updateCache(
    cache,
    metrics,
) {
    if (
        !cache ||
        typeof cache !== "object"
    ) {
        return;
    }

    setText(
        "cache-size",
        formatNumber(
            cache.size,
        ),
    );

    /*
     * Current API:
     *
     * data.cache.hit_ratio
     *
     * Fallback:
     *
     * cache_hits /
     * (cache_hits + cache_misses)
     */

    let ratio = Number(
        cache.hit_ratio,
    );

    if (!Number.isFinite(ratio)) {
        const hits = Number(
            metrics?.cache_hits,
        );

        const misses = Number(
            metrics?.cache_misses,
        );

        const total = hits + misses;

        ratio = (
            total > 0
            ? hits / total
            : 0
        );
    }

    setText(
        "cache-ratio",
        formatPercentage(
            ratio,
        ),
    );

    setText(
        "cache-hit-rate",
        formatPercentage(
            ratio,
        ),
    );

    setText(
        "cache-misses",
        formatNumber(
            metrics?.cache_misses,
        ),
    );
}


/* ==========================================================
   DNS STATUS
   ========================================================== */

function updateDNS(dns) {
    if (
        !dns ||
        typeof dns !== "object"
    ) {
        return;
    }

    const host = (
        dns.host ||
        "127.0.0.1"
    );

    const port = (
        dns.port ||
        53
    );

    const status = (
        dns.status ||
        "unknown"
    );

    setText(
        "dns-host",
        host,
    );

    setText(
        "dns-port",
        port,
    );

    setText(
        "dns-status",
        status,
    );

    setText(
        "dns-transport",
        `UDP ${host}:${port}`,
    );

    /*
     * This is the local listener, not the
     * upstream transport.
     *
     * Do not claim TLS here.
     */

    setText(
        "transport-security",
        "Local UDP",
    );
}


/* ==========================================================
   OPTIONAL BLOCKLIST DATA
   ========================================================== */

function updateOptionalSections(data) {
    /*
     * These fields may not exist in the current
     * dashboard API response.
     */

    if (
        data.blocklists &&
        typeof data.blocklists === "object"
    ) {
        setText(
            "blocklist-count",
            formatNumber(
                data.blocklists.loaded_lists,
            ),
        );

        setText(
            "blocked-domain-count",
            formatNumber(
                data.blocklists.total_domains,
            ),
        );
    }

    if (
        Array.isArray(
            data.filters,
        )
    ) {
        const enabled = data.filters.filter(
            (filter) => (
                filter &&
                filter.enabled === true
            ),
        );

        setText(
            "filter-count",
            formatNumber(
                enabled.length,
            ),
        );
    }
}


/* ==========================================================
   QUERY CHART
   ========================================================== */

function updateQueryChart(metrics) {
    const canvas = getElement(
        "query-chart",
    );

    if (
        !canvas ||
        !metrics ||
        typeof metrics !== "object"
    ) {
        return;
    }

    const context = canvas.getContext(
        "2d",
    );

    if (!context) {
        return;
    }

    const queries = Array.isArray(
        metrics.recent_queries,
    )
        ? metrics.recent_queries
        : [];

    const blocked = Array.isArray(
        metrics.recent_blocked,
    )
        ? metrics.recent_blocked
        : [];

    const queryData = queries
        .slice(-MAX_HISTORY_POINTS)
        .map(Number)
        .filter(Number.isFinite);

    const blockedData = blocked
        .slice(-MAX_HISTORY_POINTS)
        .map(Number)
        .filter(Number.isFinite);

    const width = canvas.width;
    const height = canvas.height;

    context.clearRect(
        0,
        0,
        width,
        height,
    );

    if (
        queryData.length === 0 &&
        blockedData.length === 0
    ) {
        return;
    }

    const maximum = Math.max(
        1,
        ...queryData,
        ...blockedData,
    );

    function drawLine(values) {
        if (values.length === 0) {
            return;
        }

        context.beginPath();

        values.forEach(
            (value, index) => {
                const x = (
                    index /
                    Math.max(
                        1,
                        values.length - 1,
                    )
                ) * width;

                const y = (
                    height -
                    (
                        Math.max(
                            0,
                            value,
                        ) / maximum
                    ) * height
                );

                if (index === 0) {
                    context.moveTo(
                        x,
                        y,
                    );
                } else {
                    context.lineTo(
                        x,
                        y,
                    );
                }
            },
        );

        context.stroke();
    }

    drawLine(queryData);
    drawLine(blockedData);
}


/* ==========================================================
   COMPLETE DASHBOARD UPDATE
   ========================================================== */

function updateDashboard(data) {
    if (
        !data ||
        typeof data !== "object" ||
        !data.metrics ||
        typeof data.metrics !== "object"
    ) {
        throw new Error(
            "INVALID_DASHBOARD_DATA",
        );
    }

    updateMetrics(
        data.metrics,
    );

    updateCache(
        data.cache,
        data.metrics,
    );

    updateDNS(
        data.dns,
    );

    updateOptionalSections(
        data,
    );

    updateQueryChart(
        data.metrics,
    );

    setConnectionStatus(
        true,
        "Live",
    );
}


/* ==========================================================
   REFRESH
   ========================================================== */

async function refreshDashboard() {
    if (state.refreshing) {
        return;
    }

    state.refreshing = true;

    try {
        const data = await fetchDashboard();

        updateDashboard(
            data,
        );

    } catch (error) {

        /*
         * Do not expose exception details.
         */

        if (
            error instanceof Error &&
            error.message ===
                "AUTHENTICATION_REQUIRED"
        ) {
            setConnectionStatus(
                false,
                "Authentication required",
            );

        } else if (
            error instanceof Error &&
            error.message ===
                "ACCESS_DENIED"
        ) {
            setConnectionStatus(
                false,
                "Access denied",
            );

        } else {
            setConnectionStatus(
                false,
                "Dashboard unavailable",
            );
        }

    } finally {
        state.refreshing = false;
    }
}


/* ==========================================================
   POLLING
   ========================================================== */

function startPolling() {
    if (state.timer !== null) {
        return;
    }

    state.timer = window.setInterval(
        refreshDashboard,
        REFRESH_INTERVAL_MS,
    );
}


function stopPolling() {
    if (state.timer === null) {
        return;
    }

    window.clearInterval(
        state.timer,
    );

    state.timer = null;
}


/* ==========================================================
   MOBILE SIDEBAR
   ========================================================== */

function initializeNavigation() {
    const menuButton = getElement(
        "menuButton",
    );

    const sidebar = getElement(
        "sidebar",
    );

    if (
        !menuButton ||
        !sidebar
    ) {
        return;
    }

    menuButton.addEventListener(
        "click",
        () => {
            const open =
                sidebar.classList.toggle(
                    "open",
                );

            menuButton.setAttribute(
                "aria-expanded",
                String(open),
            );
        },
    );
}


/* ==========================================================
   PAGE LIFECYCLE
   ========================================================== */

function initializeDashboard() {
    if (state.initialized) {
        return;
    }

    state.initialized = true;

    initializeNavigation();

    refreshDashboard();

    startPolling();
}


/* ==========================================================
   VISIBILITY HANDLING
   ========================================================== */

document.addEventListener(
    "visibilitychange",
    () => {

        if (
            document.visibilityState ===
            "visible"
        ) {
            refreshDashboard();
            startPolling();

        } else {
            stopPolling();
        }
    },
);


/* ==========================================================
   START
   ========================================================== */

if (
    document.readyState ===
    "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        initializeDashboard,
        {
            once: true,
        },
    );
} else {
    initializeDashboard();
}