"use strict";

const AUDIT_API = "/api/audit-log?limit=100";

function getAuditElement(id) {
    return document.getElementById(id);
}

function formatAuditTime(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

function formatDetails(value) {
    if (value === null || value === undefined) {
        return "—";
    }

    if (typeof value === "string") {
        return value;
    }

    try {
        return JSON.stringify(value);
    } catch (_error) {
        return "—";
    }
}

function appendCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value;
    row.appendChild(cell);
}

function renderAuditEvents(events) {
    const body = getAuditElement("auditTableBody");
    body.replaceChildren();

    if (!Array.isArray(events) || events.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 6;
        cell.textContent = "No audit events recorded yet.";
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const event of events) {
        const row = document.createElement("tr");
        appendCell(row, formatAuditTime(event.timestamp));
        appendCell(row, event.actor || "System");
        appendCell(row, event.action || "—");
        appendCell(row, event.result || "—");
        appendCell(row, event.resource || "—");
        appendCell(row, formatDetails(event.details));
        body.appendChild(row);
    }
}

async function loadAuditEvents() {
    const status = getAuditElement("auditStatus");
    status.textContent = "Loading audit events...";

    try {
        const response = await fetch(AUDIT_API, {
            method: "GET",
            credentials: "same-origin",
            headers: {
                Accept: "application/json",
            },
        });

        if (response.status === 401 || response.status === 403) {
            window.location.assign("/login");
            return;
        }

        if (!response.ok) {
            throw new Error("Audit log request failed.");
        }

        const data = await response.json();
        renderAuditEvents(data.events);
        status.textContent = `${Array.isArray(data.events) ? data.events.length : 0} event(s) loaded.`;
    } catch (_error) {
        status.textContent = "Unable to load audit events.";
    }
}

const refreshButton = getAuditElement("auditRefresh");
if (refreshButton) {
    refreshButton.addEventListener("click", loadAuditEvents);
}

loadAuditEvents();
