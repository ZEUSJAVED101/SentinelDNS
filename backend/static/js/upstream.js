/*
 * SentinelDNS Upstream DNS Management
 *
 * Responsibilities:
 * - Load active upstream configuration
 * - Switch between DoH / DoT / UDP
 * - Manage DoH providers
 * - Manage UDP upstream servers
 * - Apply validated configuration
 *
 * Security:
 * - Same-origin requests only
 * - Credentials are sent using browser session cookies
 * - No tokens stored in browser storage
 * - API data is rendered using textContent
 * - No innerHTML for runtime API data
 */

"use strict";


/* ==========================================================
   CONSTANTS
   ========================================================== */

const UPSTREAM_API = "/api/upstream";
const APPLY_UPSTREAM_API = "/upstream/apply";


const BUILTIN_PROVIDERS = new Set([
    "cloudflare",
    "google",
    "quad9",
]);


/* ==========================================================
   STATE
   ========================================================== */

const state = {
    configuration: null,
    loading: false,
    applying: false,
};


/* ==========================================================
   DOM HELPERS
   ========================================================== */

function getElement(id) {
    return document.getElementById(id);
}


function setText(id, value) {

    const element = getElement(id);

    if (!element) {
        return;
    }

    element.textContent = String(value);
}


function showMessage(
    message,
    type = "info",
) {

    const element = getElement(
        "upstream-message",
    );

    if (!element) {
        return;
    }

    element.textContent = message;

    element.className =
        "upstream-message " +
        `upstream-message-${type}`;
}


function clearMessage() {

    const element = getElement(
        "upstream-message",
    );

    if (!element) {
        return;
    }

    element.textContent = "";
    element.className =
        "upstream-message";
}


/* ==========================================================
   TRANSPORT
   ========================================================== */

function getSelectedTransport() {

    const selected =
        document.querySelector(
            'input[name="transport"]:checked',
        );

    if (!selected) {
        return "doh";
    }

    return selected.value
        .trim()
        .toLowerCase();
}


function updateSections() {

    const transport =
        getSelectedTransport();

    const dohSection =
        getElement("doh-section");

    const dotSection =
        getElement("dot-section");

    const udpSection =
        getElement("udp-section");

    if (dohSection) {
        dohSection.hidden =
            transport !== "doh";
    }

    if (dotSection) {
        dotSection.hidden =
            transport !== "dot";
    }

    if (udpSection) {
        udpSection.hidden =
            transport !== "udp";
    }

    updateProviderSelection();
}


/* ==========================================================
   DOH PROVIDER
   ========================================================== */

function getSelectedProvider() {

    const selected =
        document.querySelector(
            'input[name="provider"]:checked',
        );

    if (!selected) {
        return "cloudflare";
    }

    return selected.value
        .trim()
        .toLowerCase();
}


function updateProviderSelection() {


    const provider =
        getSelectedProvider();

    const customSection =
        getElement(
            "custom-doh-section",
        );

    const endpoint =
        getElement(
            "doh-endpoint",
        );

    const endpoints = {
        cloudflare:
            "https://cloudflare-dns.com/dns-query",

        google:
            "https://dns.google/dns-query",

        quad9:
            "https://dns.quad9.net/dns-query",
    };


    if (!customSection) {
        return;
    }


    const isCustom =
        provider === "custom";


    customSection.hidden =
        !isCustom;


    if (!endpoint) {
        return;
    }


    if (isCustom) {

        endpoint.disabled =
            false;

        endpoint.readOnly =
            false;

        endpoint.placeholder =
            "https://dns.example.com/dns-query";

        /*
         * Don't overwrite a custom endpoint
         * selected by the user.
         */

        return;
    }


    const selectedEndpoint =
        endpoints[provider];


    if (selectedEndpoint) {

        endpoint.value =
            selectedEndpoint;
    }


    endpoint.disabled =
        true;

    endpoint.readOnly =
        true;
}
/* ==========================================================
   UDP SERVER LIST
   ========================================================== */

function createUDPServerInput(
    value = "",
) {

    const wrapper =
        document.createElement("div");

    wrapper.className =
        "server-row";


    const input =
        document.createElement("input");

    input.type = "text";

    input.className =
        "upstream-input";

    input.dataset.udpServer =
        "true";

    input.placeholder =
        "1.1.1.1";

    input.autocomplete =
        "off";

    input.value = value;


    const removeButton =
        document.createElement("button");

    removeButton.type =
        "button";

    removeButton.className =
        "remove-server";

    removeButton.textContent =
        "Remove";


    removeButton.addEventListener(
        "click",
        () => {

            const list =
                getElement(
                    "udp-server-list",
                );

            if (!list) {
                return;
            }

            const rows =
                list.querySelectorAll(
                    ".server-row",
                );

            /*
             * Keep at least one UDP
             * server field available.
             */
            if (rows.length <= 1) {

                input.value = "";

                return;
            }

            wrapper.remove();
        },
    );


    wrapper.appendChild(input);

    wrapper.appendChild(
        removeButton,
    );

    return wrapper;
}


function setUDPServers(
    servers,
) {

    const list =
        getElement(
            "udp-server-list",
        );

    if (!list) {
        return;
    }

    list.replaceChildren();


    if (
        !Array.isArray(servers) ||
        servers.length === 0
    ) {

        list.appendChild(
            createUDPServerInput(),
        );

        return;
    }


    servers.forEach(
        server => {

            list.appendChild(
                createUDPServerInput(
                    server,
                ),
            );
        },
    );
}


function getUDPServers() {

    const inputs =
        document.querySelectorAll(
            'input[data-udp-server="true"]',
        );

    const servers = [];

    inputs.forEach(
        input => {

            const value =
                input.value.trim();

            if (value) {
                servers.push(value);
            }
        },
    );

    return servers;
}


/* ==========================================================
   ACTIVE CONFIGURATION
   ========================================================== */

function formatTransport(
    transport,
) {

    switch (transport) {

        case "doh":
            return "DNS-over-HTTPS";

        case "dot":
            return "DNS-over-TLS";

        case "udp":
            return "UDP";

        default:
            return String(
                transport || "Unknown",
            ).toUpperCase();
    }
}


function createInfoRow(
    label,
    value,
) {

    const row =
        document.createElement("div");

    row.className =
        "active-upstream-row";


    const labelElement =
        document.createElement("span");

    labelElement.className =
        "active-upstream-label";

    labelElement.textContent =
        label;


    const valueElement =
        document.createElement("span");

    valueElement.className =
        "active-upstream-value";

    valueElement.textContent =
        value;


    row.appendChild(
        labelElement,
    );

    row.appendChild(
        valueElement,
    );

    return row;
}


function renderActiveUpstream(
    info,
) {

    const container =
        getElement(
            "active-upstream",
        );

    if (!container) {
        return;
    }

    container.replaceChildren();


    if (
        !info ||
        typeof info !== "object"
    ) {

        const empty =
            document.createElement("div");

        empty.className =
            "upstream-empty";

        empty.textContent =
            "Active upstream information unavailable.";

        container.appendChild(empty);

        return;
    }


    const transport =
        String(
            info.transport || "unknown",
        ).toLowerCase();


    container.appendChild(
        createInfoRow(
            "Transport",
            formatTransport(
                transport,
            ),
        ),
    );


    if (transport === "doh") {

        if (info.provider) {

            container.appendChild(
                createInfoRow(
                    "Provider",
                    info.provider,
                ),
            );
        }

        if (info.endpoint) {

            container.appendChild(
                createInfoRow(
                    "Endpoint",
                    info.endpoint,
                ),
            );
        }

        if (
            typeof info.tls_verification
            === "boolean"
        ) {

            container.appendChild(
                createInfoRow(
                    "TLS verification",
                    info.tls_verification
                        ? "Enabled"
                        : "Disabled",
                ),
            );
        }

        if (
            typeof info.http2
            === "boolean"
        ) {

            container.appendChild(
                createInfoRow(
                    "HTTP/2",
                    info.http2
                        ? "Enabled"
                        : "Disabled",
                ),
            );
        }

    } else if (transport === "dot") {

        if (info.server) {

            container.appendChild(
                createInfoRow(
                    "Server",
                    info.server,
                ),
            );
        }

        if (info.port) {

            container.appendChild(
                createInfoRow(
                    "Port",
                    info.port,
                ),
            );
        }

        if (
            typeof info.tls_verification
            === "boolean"
        ) {

            container.appendChild(
                createInfoRow(
                    "TLS verification",
                    info.tls_verification
                        ? "Enabled"
                        : "Disabled",
                ),
            );
        }

    } else if (transport === "udp") {

        if (
            Array.isArray(
                info.servers,
            )
        ) {

            container.appendChild(
                createInfoRow(
                    "Servers",
                    info.servers.join(
                        ", ",
                    ),
                ),
            );
        }

        if (info.timeout) {

            container.appendChild(
                createInfoRow(
                    "Timeout",
                    `${info.timeout} seconds`,
                ),
            );
        }

    }


    if (
        typeof info.secure
        === "boolean"
    ) {

        container.appendChild(
            createInfoRow(
                "Encrypted",
                info.secure
                    ? "Yes"
                    : "No",
            ),
        );
    }
}


/* ==========================================================
   LOAD ACTIVE CONFIGURATION
   ========================================================== */

async function loadConfiguration() {

    if (state.loading) {
        return;
    }

    state.loading = true;

    const status =
        getElement(
            "upstream-status",
        );

    if (status) {
        status.textContent =
            "LOADING";
    }


    try {

        const response =
            await fetch(
                UPSTREAM_API,
                {
                    method: "GET",

                    credentials:
                        "same-origin",

                    headers: {
                        "Accept":
                            "application/json",
                    },

                    cache: "no-store",
                },
            );


        if (
            response.status === 401
            ||
            response.status === 403
        ) {

            throw new Error(
                "Authentication required.",
            );
        }


        if (!response.ok) {

            throw new Error(
                `Upstream API returned HTTP ${response.status}.`,
            );
        }


        const contentType =
            (
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
                "Invalid upstream API response.",
            );
        }


        const data =
            await response.json();


        if (
            !data ||
            typeof data !== "object"
        ) {

            throw new Error(
                "Invalid upstream configuration.",
            );
        }


        if (
            data.available === false
        ) {

            throw new Error(
                data.error ||
                "Upstream configuration unavailable.",
            );
        }


        const info =
            data.upstream;


        if (
            !info ||
            typeof info !== "object"
        ) {

            throw new Error(
                "Active upstream data is missing.",
            );
        }


        state.configuration =
            info;


        populateForm(
            info,
        );

        renderActiveUpstream(
            info,
        );


        if (status) {
            status.textContent =
                "LIVE";
        }


        clearMessage();

    } catch (error) {

        console.error(
            "SentinelDNS upstream load failed.",
            error,
        );


        renderActiveUpstream(
            null,
        );


        if (status) {
            status.textContent =
                "ERROR";
        }


        showMessage(
            error instanceof Error
                ? error.message
                : "Failed to load upstream configuration.",
            "error",
        );

    } finally {

        state.loading = false;
    }
}


/* ==========================================================
   POPULATE FORM
   ========================================================== */

function populateForm(
    info,
) {

    const transport =
        String(
            info.transport || "doh",
        ).toLowerCase();


    const transportInput =
        document.querySelector(
            `input[name="transport"][value="${CSS.escape(transport)}"]`,
        );


    if (transportInput) {
        transportInput.checked =
            true;
    }


    if (transport === "doh") {

        const provider =
            String(
                info.provider ||
                "cloudflare",
            ).toLowerCase();


        const providerInput =
            document.querySelector(
                `input[name="provider"][value="${CSS.escape(provider)}"]`,
            );


        if (providerInput) {
            providerInput.checked =
                true;
        }


        const endpoint =
            getElement(
                "doh-endpoint",
            );


        if (endpoint) {

            endpoint.value =
                info.endpoint || "";
        }

    }


    if (transport === "dot") {

        const server =
            getElement(
                "dot-server",
            );

        const port =
            getElement(
                "dot-port",
            );


        if (server) {
            server.value =
                info.server || "";
        }


        if (port) {
            port.value =
                info.port || 853;
        }
    }


    if (transport === "udp") {

        setUDPServers(
            info.servers || [],
        );
    }


    updateSections();
}


/* ==========================================================
   BUILD APPLY PAYLOAD
   ========================================================== */

function buildPayload() {

    const transport =
        getSelectedTransport();


    const payload = {
        transport: transport,

        udp_servers: getUDPServers(),

        udp_timeout: 5,

        udp_max_response_size: 4096,

        dot_server: "",

        dot_port: 853,

        dot_timeout: 5,

        dot_max_response_size: 4096,

        doh_provider:
            "cloudflare",

        doh_endpoint: null,

        doh_timeout: 5,

        doh_max_response_size: 4096,
    };


    if (transport === "doh") {

        payload.doh_provider =
            getSelectedProvider();


        if (
            payload.doh_provider
            === "custom"
        ) {

            const endpoint =
                getElement(
                    "doh-endpoint",
                );


            payload.doh_endpoint =
                endpoint
                    ? endpoint.value.trim()
                    : null;
        }

    }


    if (transport === "dot") {

        const server =
            getElement(
                "dot-server",
            );

        const port =
            getElement(
                "dot-port",
            );


        payload.dot_server =
            server
                ? server.value.trim()
                : "";


        payload.dot_port =
            port
                ? Number(port.value)
                : 853;
    }


    return payload;
}


/* ==========================================================
   CLIENT-SIDE VALIDATION
   ========================================================== */

function validatePayload(
    payload,
) {

    const validTransports =
        new Set([
            "udp",
            "dot",
            "doh",
        ]);


    if (
        !validTransports.has(
            payload.transport,
        )
    ) {

        throw new Error(
            "Invalid DNS transport.",
        );
    }


    if (
        payload.transport === "udp"
        &&
        payload.udp_servers.length === 0
    ) {

        throw new Error(
            "Add at least one UDP upstream server.",
        );
    }


    if (
        payload.transport === "dot"
        &&
        !payload.dot_server
    ) {

        throw new Error(
            "Enter a DoT server.",
        );
    }


    if (
        payload.transport === "dot"
        &&
        (
            !Number.isInteger(
                payload.dot_port,
            )
            ||
            payload.dot_port < 1
            ||
            payload.dot_port > 65535
        )
    ) {

        throw new Error(
            "DoT port must be between 1 and 65535.",
        );
    }


    if (
        payload.transport === "doh"
        &&
        !BUILTIN_PROVIDERS.has(
            payload.doh_provider,
        )
        &&
        payload.doh_provider !== "custom"
    ) {

        throw new Error(
            "Invalid DoH provider.",
        );
    }


    if (
        payload.transport === "doh"
        &&
        payload.doh_provider === "custom"
    ) {

        if (!payload.doh_endpoint) {

            throw new Error(
                "Enter a custom DoH endpoint.",
            );
        }


        if (
            !payload.doh_endpoint
                .toLowerCase()
                .startsWith(
                    "https://",
                )
        ) {

            throw new Error(
                "Custom DoH endpoint must use HTTPS.",
            );
        }
    }
}


/* ==========================================================
   APPLY CONFIGURATION
   ========================================================== */

async function applyConfiguration() {

    if (state.applying) {
        return;
    }


    state.applying = true;

    clearMessage();


    const button =
        getElement(
            "apply-upstream",
        );


    if (button) {

        button.disabled =
            true;

        button.textContent =
            "Applying...";
    }


    try {

        const payload =
            buildPayload();


        validatePayload(
            payload,
        );


        const response =
            await fetch(
                APPLY_UPSTREAM_API,
                {
                    method: "POST",

                    credentials:
                        "same-origin",

                    headers: {
                        "Accept":
                            "application/json",

                        "Content-Type":
                            "application/json",
                    },

                    cache: "no-store",

                    body:
                        JSON.stringify(
                            payload,
                        ),
                },
            );


        if (
            response.status === 401
            ||
            response.status === 403
        ) {

            throw new Error(
                "Authentication required.",
            );
        }


        let data = null;


        try {
            data =
                await response.json();
        } catch {
            data = null;
        }


        if (!response.ok) {

            throw new Error(
                (
                    data &&
                    data.error
                ) ||
                `Failed to apply configuration (HTTP ${response.status}).`,
            );
        }


        if (
            !data ||
            data.success !== true
        ) {

            throw new Error(
                (
                    data &&
                    data.error
                ) ||
                "Upstream configuration was not applied.",
            );
        }


        if (
            data.active_upstream
        ) {

            state.configuration =
                data.active_upstream;


            renderActiveUpstream(
                data.active_upstream,
            );


            populateForm(
                data.active_upstream,
            );
        }


        const status =
            getElement(
                "upstream-status",
            );


        if (status) {
            status.textContent =
                "LIVE";
        }


        showMessage(
            "Upstream DNS configuration applied successfully.",
            "success",
        );


    } catch (error) {

        console.error(
            "SentinelDNS upstream apply failed.",
            error,
        );


        showMessage(
            error instanceof Error
                ? error.message
                : "Failed to apply upstream configuration.",
            "error",
        );

    } finally {

        state.applying =
            false;


        if (button) {

            button.disabled =
                false;

            button.textContent =
                "Apply Changes";
        }
    }
}


/* ==========================================================
   EVENT HANDLERS
   ========================================================== */

function initializeEvents() {

    document
        .querySelectorAll(
            'input[name="transport"]',
        )
        .forEach(
            input => {

                input.addEventListener(
                    "change",
                    updateSections,
                );
            },
        );


    document
        .querySelectorAll(
            'input[name="provider"]',
        )
        .forEach(
            input => {

                input.addEventListener(
                    "change",
                    updateProviderSelection,
                );
            },
        );


    const addServer =
        getElement(
            "add-udp-server",
        );


    if (addServer) {

        addServer.addEventListener(
            "click",
            () => {

                const list =
                    getElement(
                        "udp-server-list",
                    );


                if (!list) {
                    return;
                }


                list.appendChild(
                    createUDPServerInput(),
                );
            },
        );
    }


    const refresh =
        getElement(
            "refresh-upstream",
        );


    if (refresh) {

        refresh.addEventListener(
            "click",
            loadConfiguration,
        );
    }


    const apply =
        getElement(
            "apply-upstream",
        );


    if (apply) {

        apply.addEventListener(
            "click",
            applyConfiguration,
        );
    }
}


/* ==========================================================
   INITIALIZATION
   ========================================================== */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        initializeEvents();

        updateSections();

        updateProviderSelection();

        setUDPServers([
            "1.1.1.1",
        ]);

        loadConfiguration();
    },
);