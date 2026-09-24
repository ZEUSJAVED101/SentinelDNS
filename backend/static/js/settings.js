"use strict";

const statusBadge = document.getElementById("totp-status-badge");
const stateElement = document.getElementById("totp-state");
const enrollmentElement = document.getElementById("totp-enrollment");
const startButton = document.getElementById("totp-start-button");
const qrImage = document.getElementById("totp-qr");
const secretInput = document.getElementById("totp-secret");
const copyButton = document.getElementById("copy-totp-secret");
const confirmForm = document.getElementById("totp-confirm-form");
const codeInput = document.getElementById("totp-code");
const confirmButton = document.getElementById("totp-confirm-button");
const errorElement = document.getElementById("totp-error");
const successElement = document.getElementById("totp-success");

function showError(message) {
    if (!errorElement) return;
    errorElement.textContent = message;
    errorElement.hidden = false;
}

function clearError() {
    if (!errorElement) return;
    errorElement.textContent = "";
    errorElement.hidden = true;
}

function showSuccess(message) {
    if (!successElement) return;
    successElement.textContent = message;
    successElement.hidden = false;
}

function clearSuccess() {
    if (!successElement) return;
    successElement.textContent = "";
    successElement.hidden = true;
}

function setStatus(enabled, pending) {
    if (statusBadge) {
        statusBadge.textContent = enabled ? "Enabled" : pending ? "Setup pending" : "Not enabled";
    }
}

function setLoading(button, loading, text, idleText) {
    if (!button) return;
    button.disabled = loading;
    button.textContent = loading ? text : idleText;
}

async function getStatus() {
    clearError();
    clearSuccess();

    try {
        const response = await fetch("/auth/totp/status", {
            method: "GET",
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
            cache: "no-store",
        });

        if (!response.ok) {
            throw new Error("STATUS_FAILED");
        }

        const data = await response.json();
        const enabled = data.enabled === true;
        const confirmed = data.confirmed === true;
        const pending = !enabled && confirmed === false;

        setStatus(enabled, pending && false);

        if (enabled) {
            stateElement.textContent = "Authenticator protection is enabled for this administrator account.";
            startButton.hidden = true;
            enrollmentElement.hidden = true;
            return;
        }

        stateElement.textContent = "Authenticator protection is not enabled yet. Set it up before we enforce TOTP during login.";
        startButton.hidden = false;
    } catch (error) {
        stateElement.textContent = "Unable to read TOTP status.";
        showError("Unable to load authentication settings. Please refresh the page.");
    }
}

async function startEnrollment() {
    clearError();
    clearSuccess();
    setLoading(startButton, true, "Preparing...", "Set up authenticator");

    try {
        const response = await fetch("/auth/totp/enroll", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Accept": "application/json",
            },
            cache: "no-store",
        });

        if (!response.ok) {
            throw new Error("ENROLL_FAILED");
        }

        const data = await response.json();

        if (!data.qr_code_data_uri || !data.secret) {
            throw new Error("INVALID_ENROLLMENT_RESPONSE");
        }

        qrImage.src = data.qr_code_data_uri;
        secretInput.value = data.secret;
        enrollmentElement.hidden = false;
        startButton.hidden = true;
        stateElement.textContent = "Enrollment started. Scan the QR code and confirm the generated code.";
        setStatus(false, true);
        codeInput.focus();
    } catch (error) {
        showError("Unable to start authenticator enrollment. Please try again.");
        setLoading(startButton, false, "Preparing...", "Set up authenticator");
    }
}

async function confirmEnrollment(event) {
    event.preventDefault();
    clearError();
    clearSuccess();

    const code = codeInput ? codeInput.value.trim() : "";

    if (!/^\d{6}$/.test(code)) {
        showError("Enter the 6-digit code shown in your authenticator app.");
        return;
    }

    setLoading(confirmButton, true, "Confirming...", "Confirm authenticator");

    try {
        const response = await fetch("/auth/totp/confirm", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify({ code }),
            cache: "no-store",
        });

        if (!response.ok) {
            throw new Error("CONFIRM_FAILED");
        }

        const data = await response.json();
        if (data.enabled !== true) {
            throw new Error("CONFIRM_FAILED");
        }

        enrollmentElement.hidden = true;
        startButton.hidden = true;
        stateElement.textContent = "Authenticator protection is enabled for this administrator account.";
        setStatus(true, false);
        showSuccess("Authenticator setup completed successfully.");
    } catch (error) {
        showError("The authenticator code is invalid or expired. Check your app and try again.");
        codeInput.focus();
        codeInput.select();
    } finally {
        setLoading(confirmButton, false, "Confirming...", "Confirm authenticator");
    }
}

async function copySecret() {
    clearError();

    if (!secretInput || !secretInput.value) return;

    try {
        await navigator.clipboard.writeText(secretInput.value);
        showSuccess("Setup key copied to the clipboard.");
    } catch (error) {
        secretInput.focus();
        secretInput.select();
        showSuccess("Setup key selected. Copy it manually.");
    }
}

if (startButton) {
    startButton.addEventListener("click", startEnrollment);
}

if (confirmForm) {
    confirmForm.addEventListener("submit", confirmEnrollment);
}

if (copyButton) {
    copyButton.addEventListener("click", copySecret);
}

getStatus();
