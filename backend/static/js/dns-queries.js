"use strict";

const QUERIES_API = "/api/queries/recent";
const REFRESH_INTERVAL = 5000;

let allQueries = [];

async function loadQueries() {
    const status = document.getElementById("queries-status");

    try {
        if (status) {
            status.textContent = "LOADING";
        }

        const response = await fetch(
            `${QUERIES_API}?limit=50`,
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
            if (status) {
                status.textContent = "AUTH REQUIRED";
            }
            return;
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        allQueries = Array.isArray(data.queries)
            ? data.queries
            : [];

        renderQueries();
        updateStatistics();

        if (status) {
            status.textContent = "LIVE";
        }

    } catch (error) {
        console.error("Failed to load DNS queries:", error);

        if (status) {
            status.textContent = "ERROR";
        }
    }
}


function renderQueries() {

    const tableBody = document.getElementById(
        "queries-table-body",
    );

    if (!tableBody) {
        return;
    }

    tableBody.replaceChildren();

    const domainSearch = (
        document.getElementById("query-search")?.value || ""
    ).trim().toLowerCase();

    const statusFilter = (
        document.getElementById("query-status-filter")?.value || ""
    );

    const cacheFilter = (
        document.getElementById("query-cache-filter")?.value || ""
    );

    const filtered = allQueries.filter((query) => {

        const domainMatches =
            !domainSearch ||
            String(query.domain || "")
                .toLowerCase()
                .includes(domainSearch);

        const statusMatches =
            !statusFilter ||
            query.status === statusFilter;

        const cacheMatches =
            !cacheFilter ||
            query.cache === cacheFilter;

        return (
            domainMatches &&
            statusMatches &&
            cacheMatches
        );
    });


    if (filtered.length === 0) {

        const row = document.createElement("tr");

        const cell = document.createElement("td");

        cell.colSpan = 8;
        cell.textContent = "No DNS queries recorded yet.";
        cell.className = "empty-state";

        row.appendChild(cell);
        tableBody.appendChild(row);

        return;
    }


    for (const query of filtered) {

        const row = document.createElement("tr");

        addCell(row, query.domain);
        addCell(row, query.query_type);
        addCell(row, query.status);
        addCell(row, query.cache);
        addCell(row, query.upstream);
        addCell(row, query.rcode ?? "-");
        addCell(
            row,
            `${Number(query.latency_ms || 0).toFixed(1)} ms`,
        );
        addCell(
            row,
            formatTime(query.timestamp),
        );

        tableBody.appendChild(row);
    }
}


function addCell(row, value) {

    const cell = document.createElement("td");

    cell.textContent = String(value);

    row.appendChild(cell);
}


function formatTime(timestamp) {

    if (!timestamp) {
        return "-";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return "-";
    }

    return date.toLocaleTimeString();
}


function updateStatistics() {

    setText(
        "queries-total",
        allQueries.length,
    );

    setText(
        "queries-allowed",
        allQueries.filter(
            (q) => q.status === "ALLOWED",
        ).length,
    );

    setText(
        "queries-blocked",
        allQueries.filter(
            (q) => q.status === "BLOCKED",
        ).length,
    );

    setText(
        "queries-cache-hits",
        allQueries.filter(
            (q) => q.cache === "HIT",
        ).length,
    );

    setText(
        "queries-cache-misses",
        allQueries.filter(
            (q) => q.cache === "MISS",
        ).length,
    );
}


function setText(id, value) {

    const element = document.getElementById(id);

    if (element) {
        element.textContent = String(value);
    }
}


function setupFilters() {

    const search = document.getElementById(
        "query-search",
    );

    const status = document.getElementById(
        "query-status-filter",
    );

    const cache = document.getElementById(
        "query-cache-filter",
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


document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupFilters();

        loadQueries();

        setInterval(
            loadQueries,
            REFRESH_INTERVAL,
        );
    },
);