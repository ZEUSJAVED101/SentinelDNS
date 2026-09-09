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
   DNS LOCAL LISTENER STATUS
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

    /*
     * IMPORTANT:
     *
     * This represents the LOCAL DNS listener.
     *
     * It is intentionally NOT used to display
     * the upstream transport.
     */

    setText(
        "dns-transport",
        `UDP ${host}:${port}`,
    );

    setText(
        "transport-security",
        "Local UDP",
    );
}


/* ==========================================================
   UPSTREAM TRANSPORT
   ========================================================== */

function updateTransport(transport) {
    if (
        !transport ||
        typeof transport !== "object"
    ) {
        return;
    }

    const displayName = (
        transport.display_name ||
        transport.transport ||
        "Unknown"
    );

    /*
     * Main transport label.
     */
    setText(
        "upstream-transport",
        displayName,
    );

    /*
     * Optional transport labels used by the
     * dashboard template if present.
     */
    setText(
        "active-transport",
        displayName,
    );

    /*
     * Security state.
     */
    setText(
        "upstream-security",
        transport.secure
            ? "Encrypted"
            : "Standard DNS",
    );

    /*
     * Provider / server information.
     */
    if (
        transport.provider
    ) {
        setText(
            "upstream-provider",
            transport.provider,
        );
    } else if (
        transport.server
    ) {
        setText(
            "upstream-provider",
            transport.server,
        );
    } else if (
        Array.isArray(
            transport.servers,
        ) &&
        transport.servers.length > 0
    ) {
        setText(
            "upstream-provider",
            transport.servers[0],
        );
    }

    /*
     * Endpoint.
     */
    if (
        transport.endpoint
    ) {
        setText(
            "upstream-endpoint",
            transport.endpoint,
        );
    }

    /*
     * Protocol.
     */
    if (
        transport.transport === "doh"
    ) {
        setText(
            "upstream-protocol",
            transport.http2
                ? "HTTPS / HTTP/2"
                : "HTTPS / HTTP/1.1",
        );
    } else if (
        transport.transport === "dot"
    ) {
        setText(
            "upstream-protocol",
            "TLS / DNS-over-TLS",
        );
    } else if (
        transport.transport === "udp"
    ) {
        setText(
            "upstream-protocol",
            "UDP",
        );
    }

    /*
     * TLS verification.
     */
    if (
        transport.tls_verification !== undefined
    ) {
        setText(
            "upstream-tls",
            transport.tls_verification
                ? "Enabled"
                : "Disabled",
        );
    }
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


    /*
     * THIS IS THE IMPORTANT FIX.
     *
     * The dashboard API returns:
     *
     * data.transport
     *
     * and this must be applied during every
     * dashboard refresh.
     */

    updateTransport(
        data.transport,
    );


    updateOptionalSections(
        data,
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

        const data =
            await fetchDashboard();

        updateDashboard(
            data,
        );

    } catch (error) {

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
   MANUAL REFRESH
   ========================================================== */

function initializeRefreshButton() {

    const button = getElement(
        "refreshDashboard",
    );

    if (!button) {
        return;
    }

    button.addEventListener(
        "click",
        () => {
            refreshDashboard();
        },
    );
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

    initializeRefreshButton();

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