/*
 * SentinelDNS Login
 *
 * Security principles:
 *
 * - Never stores the JWT in JavaScript storage.
 * - Never reads the authentication cookie.
 * - Browser receives the HttpOnly cookie from /auth/login.
 * - Credentials are sent only to the same-origin API.
 * - No password/token logging.
 */

"use strict";


const form = document.getElementById(
    "login-form",
);

const usernameInput = document.getElementById(
    "username",
);

const passwordInput = document.getElementById(
    "password",
);

const loginButton = document.getElementById(
    "login-button",
);

const errorElement = document.getElementById(
    "login-error",
);


function showError(message) {

    if (!errorElement) {
        return;
    }

    errorElement.textContent = message;

    errorElement.classList.add(
        "visible",
    );
}


function clearError() {

    if (!errorElement) {
        return;
    }

    errorElement.textContent = "";

    errorElement.classList.remove(
        "visible",
    );
}


function setLoading(loading) {

    if (!loginButton) {
        return;
    }

    loginButton.disabled = loading;

    loginButton.textContent = loading
        ? "Signing in..."
        : "Sign in";
}


async function login(event) {

    event.preventDefault();

    clearError();

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {

        showError(
            "Username and password are required.",
        );

        return;
    }

    setLoading(true);

    try {

        /*
         * OAuth2PasswordRequestForm expects
         * application/x-www-form-urlencoded.
         */

        const body = new URLSearchParams();

        body.set(
            "username",
            username,
        );

        body.set(
            "password",
            password,
        );

        const response = await fetch(
            "/auth/login",
            {
                method: "POST",

                credentials: "same-origin",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded",
                    "Accept":
                        "application/json",
                },

                body: body.toString(),

                cache: "no-store",
            },
        );

        if (!response.ok) {

            if (
                response.status === 401
                || response.status === 400
            ) {

                throw new Error(
                    "INVALID_CREDENTIALS",
                );
            }

            throw new Error(
                "LOGIN_FAILED",
            );
        }

        /*
         * We deliberately do NOT read or store
         * access_token from the response.
         *
         * The server has already placed the JWT
         * into an HttpOnly cookie.
         */

        window.location.assign(
            "/dashboard",
        );

    } catch (error) {

        if (
            error instanceof Error
            && error.message
                === "INVALID_CREDENTIALS"
        ) {

            showError(
                "Invalid username or password.",
            );

        } else {

            showError(
                "Unable to sign in. Please try again.",
            );
        }

    } finally {

        setLoading(false);
    }
}


if (form) {

    form.addEventListener(
        "submit",
        login,
    );
}