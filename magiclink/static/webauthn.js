(function(window) {
    const MagicLink = {
        config: {
            endpoints: {
                registerStart: '/webauthn/register/start',
                registerFinish: '/webauthn/register/finish',
                loginStart: '/webauthn/login/start',
                loginFinish: '/webauthn/login/finish',
                loginDiscoverable: '/webauthn/login/discoverable'
            }
        },

        // Internal state for conditional login
        _conditionalController: null,

        // Registration Flow
        async register(email) {
            this.abortConditionalLogin();

            try {
                const startResp = await fetch(this.config.endpoints.registerStart, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                }).then(r => r.json());

                if (startResp.error) throw new Error(startResp.error);

                const credential = await navigator.credentials.create({
                    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(startResp.options.publicKey)
                });

                const finishResp = await fetch(this.config.endpoints.registerFinish, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challenge_id: startResp.challenge_id,
                        response: credential.toJSON()
                    })
                }).then(r => r.json());

                if (finishResp.error) throw new Error(finishResp.error);
                return finishResp;

            } catch (e) {
                console.error("WebAuthn Registration Failed:", e);
                throw e;
            }
        },

        // Login Flow (User Identified)
        async login(email) {
            this.abortConditionalLogin();
            return this._loginFlow(this.config.endpoints.loginStart, { email });
        },

        // Login Flow (Discoverable / Userless)
        async loginDiscoverable() {
            this.abortConditionalLogin();
            return this._loginFlow(this.config.endpoints.loginDiscoverable, {});
        },

        // Conditional Login (Conditional Mediation)
        // Call on page load. The browser will show passkey suggestions when the user
        // focuses an <input autocomplete="username webauthn"> field.
        async conditionalLogin() {
            if (!window.PublicKeyCredential ||
                !PublicKeyCredential.isConditionalMediationAvailable) {
                return;
            }

            const available = await PublicKeyCredential.isConditionalMediationAvailable();
            if (!available) return;

            this._conditionalController = new AbortController();

            try {
                const startResp = await fetch(this.config.endpoints.loginDiscoverable, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: '{}'
                }).then(r => r.json());

                if (startResp.error) return;

                const assertion = await navigator.credentials.get({
                    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(startResp.options.publicKey),
                    mediation: 'conditional',
                    signal: this._conditionalController.signal
                });

                this._conditionalController = null;

                const finishURL = this._appendRedirect(this.config.endpoints.loginFinish);
                const finishResp = await fetch(finishURL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challenge_id: startResp.challenge_id,
                        response: assertion.toJSON()
                    })
                }).then(r => r.json());

                if (finishResp.error) throw new Error(finishResp.error);

                if (finishResp.redirect_url) {
                    window.location.href = finishResp.redirect_url;
                }

                return finishResp;

            } catch (e) {
                if (e.name === 'AbortError') return;
                throw e;
            }
        },

        // Get the redirect parameter from the current page URL
        _getRedirectParam() {
            const params = new URLSearchParams(window.location.search);
            return params.get('redirect') || '';
        },

        // Append redirect parameter to a URL if present on the current page
        _appendRedirect(url) {
            const redirect = this._getRedirectParam();
            if (redirect) {
                const sep = url.includes('?') ? '&' : '?';
                return url + sep + 'redirect=' + encodeURIComponent(redirect);
            }
            return url;
        },

        // Abort any pending conditional login (called before other auth actions)
        abortConditionalLogin() {
            if (this._conditionalController) {
                this._conditionalController.abort();
                this._conditionalController = null;
            }
        },

        async _loginFlow(endpoint, body) {
            try {
                const startResp = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }).then(r => r.json());

                if (startResp.error) throw new Error(startResp.error);

                const assertion = await navigator.credentials.get({
                    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(startResp.options.publicKey)
                });

                const finishURL = this._appendRedirect(this.config.endpoints.loginFinish);
                const finishResp = await fetch(finishURL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challenge_id: startResp.challenge_id,
                        response: assertion.toJSON()
                    })
                }).then(r => r.json());

                if (finishResp.error) throw new Error(finishResp.error);

                if (finishResp.redirect_url) {
                    window.location.href = finishResp.redirect_url;
                }

                return finishResp;

            } catch (e) {
                console.error("WebAuthn Login Failed:", e);
                throw e;
            }
        }
    };

    window.MagicLink = MagicLink;
})(window);
