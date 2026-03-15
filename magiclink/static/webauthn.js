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

        // Registration Flow
        async register(email) {
            try {
                const startResp = await fetch(this.config.endpoints.registerStart, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                }).then(r => r.json());

                if (startResp.error) throw new Error(startResp.error);

                // Use browser native API to parse creation options
                const credential = await navigator.credentials.create({
                    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(startResp.options.publicKey)
                });

                // Use credential.toJSON() for base64url serialization
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
            return this._loginFlow(this.config.endpoints.loginStart, { email });
        },

        // Login Flow (Discoverable / Userless)
        async loginDiscoverable() {
            return this._loginFlow(this.config.endpoints.loginDiscoverable, {});
        },

        async _loginFlow(endpoint, body) {
            try {
                const startResp = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }).then(r => r.json());

                if (startResp.error) throw new Error(startResp.error);

                // Use browser native API to parse request options
                const assertion = await navigator.credentials.get({
                    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(startResp.options.publicKey)
                });

                // Use assertion.toJSON() for base64url serialization
                const finishResp = await fetch(this.config.endpoints.loginFinish, {
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
