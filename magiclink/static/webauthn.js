(function(window) {
    // Utility: Base64URL to ArrayBuffer
    function bufferDecode(value) {
        return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    }

    // Utility: ArrayBuffer to Base64URL
    function bufferEncode(value) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    const MagicLink = {
        // Config will be injected or set by default
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
                // 1. Start Registration
                const startResp = await fetch(this.config.endpoints.registerStart, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                }).then(r => r.json());

                if (startResp.error) throw new Error(startResp.error);

                // 2. Prepare options for navigator.credentials.create
                // The server returns options in a format close to what browser expects, 
                // but we need to ensure binary fields are ArrayBuffers.
                // Assuming the server returns Base64URL strings for binary fields.
                const publicKey = startResp.options.publicKey;
                
                // Decode Challenge & User ID
                // challenge_id is for the server session, publicKey.challenge is the actual WebAuthn challenge
                publicKey.challenge = bufferDecode(publicKey.challenge); 
                if (publicKey.user && publicKey.user.id) {
                     // If it's already a string, decode it. If library handles it differently, adjust here.
                     // The `go-webauthn` library usually returns `user.id` as a string in JSON.
                     publicKey.user.id = bufferDecode(publicKey.user.id);
                }

                // 3. Create Credentials
                const credential = await navigator.credentials.create({ publicKey });

                // 4. Finish Registration
                const finishReq = {
                    challenge_id: startResp.challenge_id,
                    response: {
                        id: credential.id,
                        rawId: bufferEncode(credential.rawId),
                        type: credential.type,
                        response: {
                            attestationObject: bufferEncode(credential.response.attestationObject),
                            clientDataJSON: bufferEncode(credential.response.clientDataJSON)
                        }
                    }
                };

                const finishResp = await fetch(this.config.endpoints.registerFinish, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(finishReq)
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
                // 1. Start Login
                const startResp = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }).then(r => r.json());

                if (startResp.error) throw new Error(startResp.error);

                // 2. Prepare options
                // In `handlers/webauthn.go`, `convertCredentialAssertionForBrowser` handles conversion carefully.
                // It returns `challenge` as Base64URL string.
                const options = startResp.options;
                options.challenge = bufferDecode(options.challenge);

                // AllowCredentials need ID decoding
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(c => {
                        c.id = bufferDecode(c.id);
                        return c;
                    });
                }

                // 3. Get Credentials
                const assertion = await navigator.credentials.get({ publicKey: options });

                // 4. Finish Login
                const finishReq = {
                    challenge_id: startResp.challenge_id,
                    response: {
                        id: assertion.id,
                        rawId: bufferEncode(assertion.rawId),
                        type: assertion.type,
                        response: {
                            authenticatorData: bufferEncode(assertion.response.authenticatorData),
                            clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                            signature: bufferEncode(assertion.response.signature),
                            userHandle: assertion.response.userHandle ? bufferEncode(assertion.response.userHandle) : null
                        }
                    }
                };

                const finishResp = await fetch(this.config.endpoints.loginFinish, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(finishReq)
                }).then(r => r.json());

                if (finishResp.error) throw new Error(finishResp.error);
                
                // If redirect URL is provided, redirect
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
