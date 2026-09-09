"use strict";

(() => {
    const refreshButton = document.getElementById("dhcpRefresh");
    const message = document.getElementById("dhcpMessage");
    const rows = document.getElementById("dhcpLeaseRows");

    if (!refreshButton || !message || !rows) {
        return;
    }

    const byId = (id) => document.getElementById(id);

    const setText = (id, value) => {
        const element = byId(id);
        if (element) {
            element.textContent = value;
        }
    };

    const setMessage = (text, type = "") => {
        message.textContent = text;
        message.className = `dhcp-message ${type}`.trim();
        message.hidden = !text;
    };

    const formatDuration = (seconds) => {
        const total = Math.max(0, Number(seconds) || 0);
        const days = Math.floor(total / 86400);
        const hours = Math.floor((total % 86400) / 3600);
        const minutes = Math.floor((total % 3600) / 60);

        if (days > 0) {
            return `${days}d ${hours}h`;
        }
        if (hours > 0) {
            return `${hours}h ${minutes}m`;
        }
        return `${minutes}m`;
    };

    const formatDate = (value) => {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return "Unknown";
        }
        return date.toLocaleString();
    };

    const appendCell = (row, value, className = "") => {
        const cell = document.createElement("td");
        if (className) {
            cell.className = className;
        }
        cell.textContent = value;
        row.appendChild(cell);
    };

    const renderLeases = (leases) => {
        rows.replaceChildren();

        if (!Array.isArray(leases) || leases.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.className = "dhcp-empty";
            cell.textContent = "No persistent DHCP lease records found.";
            row.appendChild(cell);
            rows.appendChild(row);
            return;
        }

        for (const lease of leases) {
            const row = document.createElement("tr");
            appendCell(row, lease.client_id || "Unknown", "dhcp-client-id");
            appendCell(row, lease.hostname || "—");
            appendCell(row, lease.ip_address || "Unknown", "dhcp-ip");
            appendCell(row, lease.state || "Unknown", `dhcp-state ${String(lease.state || "").toLowerCase()}`);
            appendCell(row, formatDate(lease.lease_end));
            appendCell(row, lease.state === "ACTIVE" ? formatDuration(lease.remaining_seconds) : "Expired");
            rows.appendChild(row);
        }
    };

    const render = (data) => {
        const enabled = data.enabled === true;
        const active = Number(data.active_leases) || 0;
        const poolSize = Number(data.pool_size) || 0;
        const utilization = poolSize > 0 ? Math.min(100, (active / poolSize) * 100) : 0;

        setText("dhcpEnabled", enabled ? "ENABLED" : "DISABLED");
        setText("dhcpActiveLeases", String(active));
        setText("dhcpExpiredLeases", String(Number(data.expired_leases) || 0));
        setText("dhcpPoolSize", String(poolSize));
        setText("dhcpListen", `${data.listen_host}:${data.listen_port}`);
        setText("dhcpInterface", data.interface || "Default interface");
        setText("dhcpServerIp", data.server_ip);
        setText("dhcpSubnet", data.subnet_mask);
        setText("dhcpGateway", data.gateway);
        setText("dhcpDns", data.dns_server);
        setText("dhcpLeaseTime", formatDuration(data.lease_time));
        setText("dhcpPoolRange", `${data.pool_start} — ${data.pool_end}`);
        setText("dhcpConfigBadge", enabled ? "Configured" : "Disabled");
        setText("dhcpPoolConfigured", String(poolSize));
        setText("dhcpPoolActive", String(active));
        setText("dhcpPoolUtilization", `${utilization.toFixed(1)}%`);
        setText("dhcpLeaseCount", `${Array.isArray(data.leases) ? data.leases.length : 0} record(s)`);

        const progress = byId("dhcpProgressFill");
        if (progress) {
            progress.style.width = `${utilization}%`;
        }

        renderLeases(data.leases);
    };

    const load = async () => {
        refreshButton.disabled = true;
        setMessage("");

        try {
            const response = await fetch("/api/dhcp", {
                method: "GET",
                credentials: "same-origin",
                headers: {
                    "Accept": "application/json",
                },
                cache: "no-store",
            });

            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    throw new Error("Authentication is required to view DHCP information.");
                }
                throw new Error("Unable to load DHCP information.");
            }

            const data = await response.json();
            render(data);
        } catch (error) {
            rows.replaceChildren();
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.className = "dhcp-empty dhcp-error-text";
            cell.textContent = "DHCP information could not be loaded.";
            row.appendChild(cell);
            rows.appendChild(row);
            setMessage(error instanceof Error ? error.message : "Unable to load DHCP information.", "error");
        } finally {
            refreshButton.disabled = false;
        }
    };

    refreshButton.addEventListener("click", load);
    load();
})();
