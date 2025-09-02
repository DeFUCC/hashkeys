export async function PassKeyAuth(name) {
  if (!name) return;

  const id = crypto.getRandomValues(new Uint8Array(16))
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengeBase64url = btoa(String.fromCharCode(...challenge)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  try {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "Intelligraphs" },
        user: {
          id,
          name,
          displayName: name,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "preferred",
        },
        attestation: "none",
        timeout: 60000,
      },
    });

    if (JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON))?.challenge != challengeBase64url) return false;

    return credential.rawId
  } catch (error) {
    console.error("Error creating passkey:", error);
    return false;
  }
}

export async function PassKeyLogin() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengeBase64url = btoa(String.fromCharCode(...challenge)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge,
        userVerification: "preferred",
        timeout: 60000,
      },
    });
    if (JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON))?.challenge != challengeBase64url) return false;
    return credential.rawId

  } catch (error) {
    console.error("Error during passkey login:", error);
    return false;
  }
}
