import { createServer } from "http";
import { randomBytes, createHmac } from "crypto";

// ─── Config ───────────────────────────────────────────────────────────────────

const OCULUS_API_KEY   = process.env.OCULUS_API_KEY  || "OC|appid|secret";
const VALID_PACKAGE    = process.env.VALID_PACKAGE   || "com.company.product";
const VALID_CERT       = process.env.VALID_CERT      || "your_sha256_cert_hash";
const DISCORD_WEBHOOK  = process.env.DISCORD_WEBHOOK_URL || "";
const PORT             = process.env.PORT || 7080;

// In-memory nonce store (mirrors Python's currentNonces dict)
const currentNonces = {};

// ─── Oculus API ───────────────────────────────────────────────────────────────

async function AttestationAuthentication(AttestationToken) {
  const url =
    `https://graph.oculus.com/platform_integrity/verify` +
    `?token=${encodeURIComponent(AttestationToken)}&access_token=${OCULUS_API_KEY}`;
  const resp = await fetch(url);
  return resp.json();
}

async function VerifyOculusStandards(userId, nonce) {
  const validateRes = await fetch("https://graph.oculus.com/user_nonce_validate", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ access_token: OCULUS_API_KEY, nonce, user_id: userId }),
  });

  let validationData;
  try { validationData = await validateRes.json(); }
  catch { return { is_valid: false, org_scoped_id: null }; }

  if (!validationData.is_valid) return { is_valid: false, org_scoped_id: null };

  const orgRes = await fetch(
    `https://graph.oculus.com/${userId}?access_token=${OCULUS_API_KEY}&fields=org_scoped_id`
  );
  let orgData;
  try { orgData = await orgRes.json(); }
  catch { return { is_valid: true, org_scoped_id: null }; }

  return { is_valid: true, org_scoped_id: orgData.org_scoped_id ?? null };
}

// ─── Discord Webhooks ─────────────────────────────────────────────────────────

function deviceEmoji(device = "") {
  const d = device.toLowerCase();
  if (d.includes("3s") || d.includes("panther")) return "🥽";
  if (d.includes("3")  || d.includes("eureka"))  return "🎮";
  return "🕹️";
}

async function postWebhook(payload) {
  if (!DISCORD_WEBHOOK) return;
  await fetch(DISCORD_WEBHOOK, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(() => {});
}

async function WebhookAttestSuccess({ ip, device, metaUser, userId, orgScopedId, nonce, claims, timeTook }) {
  await postWebhook({
    embeds: [{
      title: "✅  Attestation Success",
      color: 0x57f287,
      fields: [
        { name: "IP | Device",       value: `\`${ip}\` | ${deviceEmoji(device)} **${device}**`, inline: false },
        { name: "Meta User",         value: `**${metaUser}**`,                                  inline: true  },
        { name: "UserId | OrgScoped",value: `\`${userId}\` | \`${orgScopedId}\``,              inline: false },
        { name: "Nonce",             value: `\`\`\`\n${nonce}\n\`\`\``,                         inline: false },
        { name: "Attestation Claims",value: `\`\`\`json\n${JSON.stringify(claims, null, 2)}\n\`\`\``, inline: false },
      ],
      footer: { text: `Time Took: ${timeTook}ms` },
      timestamp: new Date().toISOString(),
    }],
  });
}

async function WebhookAttestFailed({ ip, device, reason, claims, timeTook }) {
  await postWebhook({
    embeds: [{
      title: "❌  Attestation Failed",
      color: 0xed4245,
      fields: [
        { name: "IP | Device", value: `\`${ip}\` | ${deviceEmoji(device)} **${device}**`, inline: false },
        { name: "Reason",      value: `\`\`\`\n${reason}\n\`\`\``,                         inline: false },
        { name: "Raw Claims",  value: `\`\`\`json\n${JSON.stringify(claims ?? {}, null, 2)}\n\`\`\``, inline: false },
      ],
      footer: { text: `Time Took: ${timeTook}ms` },
      timestamp: new Date().toISOString(),
    }],
  });
}

async function WebhookPhotonAuth({ ip, metaUser, oculusId, playfabId, orgScopedId, timeTook, method = "GET" }) {
  await postWebhook({
    embeds: [{
      title: `🔗  Photon Auth Success (${method})`,
      color: 0x5865f2,
      fields: [
        { name: "IP Address",    value: `\`${ip}\``,          inline: false },
        { name: "Meta User",     value: `**${metaUser}**`,    inline: true  },
        { name: "Oculus ID",     value: `\`${oculusId}\``,    inline: true  },
        { name: "PlayFab ID",    value: `\`${playfabId}\``,   inline: true  },
        { name: "Org Scoped ID", value: `\`${orgScopedId}\``, inline: false },
      ],
      footer: { text: `Time Took: ${timeTook}ms` },
      timestamp: new Date().toISOString(),
    }],
  });
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

async function GetNonce(req, res, body) {
  const data    = JSON.parse(body);
  const userId  = data.UserId;
  const nonce   = data.Nonce;

  if (!userId)
    return send(res, 400, { error: "The user id provided is null, empty or undefined" });
  if (!nonce)
    return send(res, 400, { error: "The nonce provided is null, empty or undefined" });

  let verification;
  try { verification = await VerifyOculusStandards(userId, nonce); }
  catch (e) { return send(res, 500, { error: "Oculus verification failed: " + e.message }); }

  if (!verification.is_valid)
    return send(res, 403, { error: "The user information details provided are invalid and or undefined" });

  const challengeNonce = randomBytes(16).toString("base64url");
  currentNonces[userId] = challengeNonce;

  return send(res, 200, {
    challenge_nonce: challengeNonce,
    org_scoped_id:   verification.org_scoped_id,
  });
}

async function MotherShipAuth(req, res, body) {
  const start  = Date.now();
  const ip     = req.headers["x-forwarded-for"]?.split(",")[0].trim() ?? req.socket?.remoteAddress ?? "0.0.0.0";
  const device = req.headers["x-device-model"] ?? "Unknown Device";

  const rjson          = JSON.parse(body);
  const userId         = rjson.UserId;
  const AttestationToken = rjson.AttestationToken;

  if (!AttestationToken || AttestationToken.trim() === "") {
    await WebhookAttestFailed({ ip, device, reason: "INTEGRITY_FAILED - Token is null or empty", claims: {}, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership authentication attestation token is null or empty.",
      BanExpirationTime: "Unknown",
    });
  }

  let data;
  try { data = await AttestationAuthentication(AttestationToken); }
  catch (e) { return send(res, 500, { error: "Attestation request failed: " + e.message }); }

  if (!data?.data || data.data.length === 0) {
    await WebhookAttestFailed({ ip, device, reason: "INTEGRITY_FAILED - Oculus returned empty data", claims: {}, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership authentication responded with a value less then 1, the attestation authentication must return a value greater then 0 and not less then 0, example: 1, 2, 3, 4. But the response is less then 1. eg: the Validation responded with null or empty data.",
      BanExpirationTime: "Unkown",
    });
  }

  const response_data = data.data[0];

  if (response_data.message === "invalid signature") {
    await WebhookAttestFailed({ ip, device, reason: "INTEGRITY_FAILED - Invalid signature", claims: {}, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with a invalid attestation token authentication signature, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to you token having an invalid signature.",
      BanExpirationTime: "Unkown",
    });
  }

  if (response_data.message === "token expired") {
    await WebhookAttestFailed({ ip, device, reason: "INTEGRITY_FAILED - Token expired", claims: {}, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with your attestation token authentication being expired, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to your token being expired.",
      BanExpirationTime: "Unkown",
    });
  }

  if (response_data.message !== "success") {
    await WebhookAttestFailed({ ip, device, reason: `INTEGRITY_FAILED - Unexpected: ${response_data.message}`, claims: {}, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with your attestation token authentication being a invalid token, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to your token being invalid and not a valid attestation authentication request.",
      BanExpirationTime: "Unkown",
    });
  }

  // Decode claims
  let claims_json;
  try {
    const padded = (response_data.claims ?? "").replace(/-/g, "+").replace(/_/g, "/");
    claims_json = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
  } catch (e) {
    return send(res, 500, { error: "Failed to decode attestation claims: " + e.message });
  }

  const request_details = claims_json.request_details ?? {};
  const app_state       = claims_json.app_state       ?? {};
  const device_state    = claims_json.device_state    ?? {};
  const device_ban      = claims_json.device_ban      ?? {};
  const security_state  = claims_json.device_state    ?? {};

  const unique_id              = device_state.unique_id;
  const device_integrity_state = device_state.device_integrity_state;
  const StoreRecognized        = app_state.app_integrity_state;
  const securityUpdate         = security_state.security_update_pending_days;
  const packageId              = app_state.package_id;
  const Sha256Sig              = app_state.package_cert_sha256_digest ?? [];
  const device_ban_status      = device_ban.is_banned ?? false;

  if (Sha256Sig.length === 0 || !Sha256Sig.includes(VALID_CERT)) {
    await WebhookAttestFailed({ ip, device, reason: `INTEGRITY_FAILED - Cert unrecognized: ${Sha256Sig[0] ?? "null"}`, claims: claims_json, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication has rejected your request due to your package cert being unrecognized.",
      BanExpirationTime: "Unknown",
    });
  }

  if (device_ban_status) {
    await WebhookAttestFailed({ ip, device, reason: `DEVICE_BANNED - unique_id: ${unique_id}`, claims: claims_json, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "Your device is currently banned from this application.",
      BanExpirationTime: device_ban.remaining_ban_time ?? "Unknown",
    });
  }

  if (!unique_id || !device_integrity_state || !StoreRecognized || !packageId || Sha256Sig.length === 0) {
    await WebhookAttestFailed({ ip, device, reason: "INTEGRITY_FAILED - Null or missing claims fields", claims: claims_json, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with no data. the data must be greater then 0, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to the authentication response return is null or empty or less then 1.",
      BanExpirationTime: "Unkown",
    });
  }

  if (packageId !== VALID_PACKAGE) {
    await WebhookAttestFailed({ ip, device, reason: `INTEGRITY_FAILED - Package mismatch: ${packageId}`, claims: claims_json, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with your package id being a unkown package cert, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to the authentication response returning a unkown package cert.",
      BanExpirationTime: "Unkown",
    });
  }

  if (device_integrity_state !== "Advanced") {
    await WebhookAttestFailed({ ip, device, reason: `INTEGRITY_FAILED - Got: ${device_integrity_state}`, claims: claims_json, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with your device integrity state being untrusted, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to the authentication response returning your device integrity state being untrusted.",
      BanExpirationTime: "Unkown",
    });
  }

  if (StoreRecognized !== "StoreRecognized") {
    await WebhookAttestFailed({ ip, device, reason: `INTEGRITY_FAILED - App state: ${StoreRecognized}`, claims: claims_json, timeTook: Date.now() - start });
    return send(res, 403, {
      BanMessage: "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership attestation authentication responded with your download source being a invalid download director source, please check you are on the latest version of the game. The attestation authentication has refused your authentication request due to the authentication response returning your download source being unrecongnised.",
      BanExpirationTime: "Unkown",
    });
  }

  const timeTook = Date.now() - start;

  await WebhookAttestSuccess({
    ip,
    device,
    metaUser:    userId ?? "Unknown",
    userId:      userId ?? "Unknown",
    orgScopedId: claims_json.user?.org_scoped_id ?? "N/A",
    nonce:       request_details.nonce ?? "N/A",
    claims:      claims_json,
    timeTook,
  });

  return send(res, 200, {
    "Success!": "OCULUS INTEGRITY AUTHENTICATION PASSED. REASON: The mothership attestation authentication responded with your authentication validation being valid",
  });
}

async function PhotonAuth(req, res, body) {
  const start = Date.now();
  const ip    = req.headers["x-forwarded-for"]?.split(",")[0].trim() ?? req.socket?.remoteAddress ?? "0.0.0.0";
  const data  = JSON.parse(body);

  const { MetaUser, OculusId, PlayFabId, OrgScopedId, Method = "GET" } = data;

  if (!OculusId)
    return send(res, 400, { error: "OculusId is null or empty" });

  const timeTook = Date.now() - start;

  await WebhookPhotonAuth({
    ip,
    metaUser:   MetaUser   ?? "Unknown",
    oculusId:   OculusId,
    playfabId:  PlayFabId  ?? "N/A",
    orgScopedId:OrgScopedId ?? "N/A",
    timeTook,
    method: Method,
  });

  return send(res, 200, { ok: true });
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

function send(res, status, obj) {
  const json = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => { data += chunk; });
    req.on("end", () => resolve(data || "{}"));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  const url    = req.url?.split("?")[0];
  const method = req.method;

  let body = "{}";
  if (method === "POST") {
    try { body = await readBody(req); }
    catch { return send(res, 400, { error: "Invalid body" }); }
  }

  try {
    if (method === "POST" && url === "/api/authenticate/attestation/getNonce")
      return await GetNonce(req, res, body);

    if (method === "POST" && url === "/api/authenticate/attestation/mothershipAuth")
      return await MotherShipAuth(req, res, body);

    if (method === "POST" && url === "/api/photon-auth")
      return await PhotonAuth(req, res, body);

    if (method === "GET" && url === "/api/health")
      return send(res, 200, { ok: true });

    send(res, 404, { error: "Not found" });
  } catch (e) {
    console.error(e);
    send(res, 500, { error: e.message });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[server] listening on port ${PORT}`);
});
