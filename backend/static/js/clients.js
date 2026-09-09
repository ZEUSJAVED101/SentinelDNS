"use strict";

(() => {
    const refreshButton = document.getElementById("clientsRefresh");
    const searchInput = document.getElementById("clientsSearch");
    const message = document.getElementById("clientsMessage");
    const rows = document.getElementById("clientsRows");
    const reserveButton = document.getElementById("clientsReserve");
    const excludeButton = document.getElementById("clientsExclude");
    const clearButton = document.getElementById("clientsClearSelection");
    const selectionCount = document.getElementById("clientsSelectionCount");

    if (!refreshButton || !searchInput || !message || !rows || !reserveButton || !excludeButton || !clearButton || !selectionCount) return;

    const selected = new Set();
    let latestClients = [];

    const byId = (id) => document.getElementById(id);
    const setText = (id, value) => { const el = byId(id); if (el) el.textContent = value; };
    const setMessage = (text) => { message.textContent = text; message.hidden = !text; };

    const formatDuration = (seconds) => {
        const total = Math.max(0, Number(seconds) || 0);
        const days = Math.floor(total / 86400);
        const hours = Math.floor((total % 86400) / 3600);
        const minutes = Math.floor((total % 3600) / 60);
        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    };

    const formatDate = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
    };

    const appendCell = (row, value, className = "") => {
        const cell = document.createElement("td");
        if (className) cell.className = className;
        cell.textContent = value;
        row.appendChild(cell);
        return cell;
    };

    const updateSelectionUi = () => {
        const count = selected.size;
        selectionCount.textContent = `${count} selected`;
        reserveButton.disabled = count === 0;
        excludeButton.disabled = count === 0;
        clearButton.disabled = count === 0;
    };

    const addPolicyBadge = (row, client) => {
        const cell = document.createElement("td");
        const wrapper = document.createElement("div");
        wrapper.className = "clients-policy";

        if (client.reserved) {
            const badge = document.createElement("span");
            badge.className = "clients-policy-badge reserved";
            badge.textContent = "RESERVED";
            wrapper.appendChild(badge);
        } else if (client.excluded) {
            const badge = document.createElement("span");
            badge.className = "clients-policy-badge excluded";
            badge.textContent = "EXCLUDED";
            wrapper.appendChild(badge);
        } else {
            const badge = document.createElement("span");
            badge.className = "clients-policy-badge dynamic";
            badge.textContent = "DYNAMIC";
            wrapper.appendChild(badge);
        }
        cell.appendChild(wrapper);
        row.appendChild(cell);
    };

    const addActionCell = (row, client) => {
        const cell = document.createElement("td");
        const button = document.createElement("button");
        button.type = "button";
        button.className = "clients-row-action";

        if (client.reserved) {
            button.textContent = "Remove reservation";
            button.addEventListener("click", () => removeReservation(client.client_id));
        } else if (client.excluded) {
            button.textContent = "Remove exclusion";
            button.addEventListener("click", () => removeExclusion(client.ip_address));
        } else {
            button.textContent = "Manage";
            button.addEventListener("click", () => {
                selected.clear();
                selected.add(client.client_id);
                updateSelectionUi();
                document.querySelectorAll(".clients-select-checkbox").forEach((box) => {
                    box.checked = box.value === client.client_id;
                });
            });
        }
        cell.appendChild(button);
        row.appendChild(cell);
    };

    const renderRows = (clients) => {
        latestClients = Array.isArray(clients) ? clients : [];
        const visibleIds = new Set(latestClients.map((client) => client.client_id));
        for (const id of [...selected]) if (!visibleIds.has(id)) selected.delete(id);
        rows.replaceChildren();

        if (latestClients.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 9;
            cell.className = "clients-empty";
            cell.textContent = "No matching DHCP client records found.";
            row.appendChild(cell);
            rows.appendChild(row);
            updateSelectionUi();
            return;
        }

        for (const client of latestClients) {
            const row = document.createElement("tr");
            const selectCell = document.createElement("td");
            selectCell.className = "clients-select-col";
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.className = "clients-select-checkbox";
            checkbox.value = client.client_id || "";
            checkbox.checked = selected.has(client.client_id);
            checkbox.setAttribute("aria-label", `Select ${client.client_id || "client"}`);
            checkbox.addEventListener("change", () => {
                if (checkbox.checked) selected.add(client.client_id);
                else selected.delete(client.client_id);
                updateSelectionUi();
            });
            selectCell.appendChild(checkbox);
            row.appendChild(selectCell);

            appendCell(row, client.client_id || "Unknown", "clients-client-id");
            appendCell(row, client.hostname || "—");
            appendCell(row, client.ip_address || "Unknown", "clients-ip");

            const stateCell = document.createElement("td");
            const badge = document.createElement("span");
            badge.className = `clients-state ${client.state === "ACTIVE" ? "active" : "expired"}`;
            badge.textContent = client.state || "Unknown";
            stateCell.appendChild(badge);
            row.appendChild(stateCell);

            addPolicyBadge(row, client);
            appendCell(row, formatDate(client.lease_end));
            appendCell(row, client.state === "ACTIVE" ? formatDuration(client.remaining_seconds) : "Expired");
            addActionCell(row, client);
            rows.appendChild(row);
        }
        updateSelectionUi();
    };

    const render = (data) => {
        const total = Number(data.total_matching) || 0;
        const active = Number(data.active) || 0;
        const expired = Number(data.expired) || 0;
        const returned = Number(data.returned) || 0;
        setText("clientsTotal", String(total));
        setText("clientsActive", String(active));
        setText("clientsReservations", String(Number(data.reservations) || 0));
        setText("clientsExclusions", String(Number(data.exclusions) || 0));
        setText("clientsCount", `${returned} displayed`);
        setText("clientsResultSummary", total > returned ? `Showing ${returned} of ${total} matching records` : `${total} matching record(s)`);
        renderRows(data.clients);
    };

    const load = async () => {
        refreshButton.disabled = true;
        setMessage("");
        const search = searchInput.value.trim();
        const query = search ? `?search=${encodeURIComponent(search)}` : "";
        try {
            const response = await fetch(`/api/clients${query}`, { method: "GET", credentials: "same-origin", headers: { "Accept": "application/json" }, cache: "no-store" });
            if (!response.ok) {
                if (response.status === 401 || response.status === 403) throw new Error("Authentication is required to view client information.");
                throw new Error("Unable to load client information.");
            }
            render(await response.json());
        } catch (error) {
            rows.replaceChildren();
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 9;
            cell.className = "clients-empty clients-error-text";
            cell.textContent = "Client information could not be loaded.";
            row.appendChild(cell);
            rows.appendChild(row);
            setMessage(error instanceof Error ? error.message : "Unable to load client information.");
        } finally {
            refreshButton.disabled = false;
        }
    };

    const postSelected = async (endpoint, confirmText) => {
        const clientIds = [...selected];
        if (!clientIds.length) return;
        if (!window.confirm(confirmText)) return;
        reserveButton.disabled = true;
        excludeButton.disabled = true;
        try {
            const response = await fetch(endpoint, {
                method: "POST",
                credentials: "same-origin",
                headers: { "Accept": "application/json", "Content-Type": "application/json" },
                body: JSON.stringify({ client_ids: clientIds }),
                cache: "no-store",
            });
            if (!response.ok && response.status !== 207) throw new Error("The requested DHCP policy could not be applied.");
            const data = await response.json();
            setMessage(`${data.succeeded} of ${data.requested} selected client(s) updated.${data.failed ? ` ${data.failed} failed.` : ""}`);
            selected.clear();
            await load();
        } catch (error) {
            setMessage(error instanceof Error ? error.message : "The DHCP policy action failed.");
            updateSelectionUi();
        }
    };

    const removeReservation = async (clientId) => {
        if (!window.confirm(`Remove the static reservation for ${clientId}?`)) return;
        try {
            const response = await fetch(`/api/clients/reservations/${encodeURIComponent(clientId)}`, { method: "DELETE", credentials: "same-origin", headers: { "Accept": "application/json" }, cache: "no-store" });
            if (!response.ok) throw new Error("The reservation could not be removed.");
            setMessage("Reservation removed.");
            await load();
        } catch (error) { setMessage(error instanceof Error ? error.message : "The reservation could not be removed."); }
    };

    const removeExclusion = async (ip) => {
        if (!window.confirm(`Allow ${ip} to be used by dynamic DHCP allocation again?`)) return;
        try {
            const response = await fetch(`/api/clients/exclusions/${encodeURIComponent(ip)}`, { method: "DELETE", credentials: "same-origin", headers: { "Accept": "application/json" }, cache: "no-store" });
            if (!response.ok) throw new Error("The exclusion could not be removed.");
            setMessage("Exclusion removed.");
            await load();
        } catch (error) { setMessage(error instanceof Error ? error.message : "The exclusion could not be removed."); }
    };

    searchInput.addEventListener("input", () => {
        window.clearTimeout(searchInput._sentinelTimer);
        searchInput._sentinelTimer = window.setTimeout(load, 250);
    });
    refreshButton.addEventListener("click", load);
    reserveButton.addEventListener("click", () => postSelected("/api/clients/reservations", "Create persistent DHCP reservations for the selected clients using their current pool IPs?"));
    excludeButton.addEventListener("click", () => postSelected("/api/clients/exclusions", "Exclude the selected clients' current IPs from future dynamic DHCP allocation? Active leases are protected and will not be altered."));
    clearButton.addEventListener("click", () => { selected.clear(); renderRows(latestClients); });

    load();
})();
