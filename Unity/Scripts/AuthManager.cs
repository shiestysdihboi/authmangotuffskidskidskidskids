using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

// ─── Config ───────────────────────────────────────────────────────────────────

public class GameInfo
{
    public string ServerUrl = "https://your-server.com";
}

// ─── Auth Manager ─────────────────────────────────────────────────────────────

public class AuthManager : MonoBehaviour
{
    private static AuthManager _instance;
    private static readonly GameInfo settings = new GameInfo();

    // Fired after full auth passes — passes org_scoped_id
    public static event Action<string> OnAuthPassed;

    // Fired if any step fails — passes ban/error message
    public static event Action<string> OnAuthFailed;

    private void Awake()
    {
        if (_instance != null && _instance != this) { Destroy(gameObject); return; }
        _instance = this;
        DontDestroyOnLoad(gameObject);
    }

    private void Start()
    {
        StartCoroutine(RunAuth());
    }

    // ─── Step 1: Get platform nonce from Oculus, send to getNonce ────────────

    private IEnumerator RunAuth()
    {
        // Get platform nonce from Oculus SDK
        string platformNonce = null;
        bool nonceReady = false;

        Oculus.Platform.Core.Initialize();
        Oculus.Platform.Users.GetUserProof().OnComplete(msg =>
        {
            nonceReady = true;
            if (!msg.IsError) platformNonce = msg.Data?.Value;
        });
        yield return new WaitUntil(() => nonceReady);

        if (string.IsNullOrEmpty(platformNonce))
        {
            FireFailed("Failed to get platform nonce from Oculus SDK.");
            yield break;
        }

        // Get logged-in user ID
        string userId = null;
        bool userReady = false;

        Oculus.Platform.Users.GetLoggedInUser().OnComplete(msg =>
        {
            userReady = true;
            if (!msg.IsError) userId = msg.Data?.ID.ToString();
        });
        yield return new WaitUntil(() => userReady);

        if (string.IsNullOrEmpty(userId))
        {
            FireFailed("Failed to get UserId from Oculus SDK.");
            yield break;
        }

        // ─── POST /api/authenticate/attestation/getNonce ──────────────────────

        string getNonceBody = $"{{\"UserId\":\"{userId}\",\"Nonce\":\"{platformNonce}\"}}";
        string challengeNonce = null;
        string orgScopedId = null;
        bool getNonceDone = false;

        yield return PostJson(
            "/api/authenticate/attestation/getNonce",
            getNonceBody,
            null,
            (code, responseBody) =>
            {
                getNonceDone = true;

                if (code == 200)
                {
                    GetNonceResponse resp = JsonUtility.FromJson<GetNonceResponse>(responseBody);
                    challengeNonce = resp.challenge_nonce;
                    orgScopedId    = resp.org_scoped_id;
                }
                else
                {
                    ErrorResponse err = JsonUtility.FromJson<ErrorResponse>(responseBody);
                    FireFailed(err?.error ?? "getNonce failed: " + responseBody);
                }
            }
        );

        if (string.IsNullOrEmpty(challengeNonce)) yield break;

        // ─── Step 2: Get attestation token signed with challenge nonce ────────

        string attestToken = null;
        bool tokenReady = false;

        Oculus.Platform.DeviceApplicationIntegrity.GetIntegrityToken(challengeNonce)
            .OnComplete(msg =>
            {
                tokenReady = true;
                if (!msg.IsError) attestToken = msg.Data;
            });
        yield return new WaitUntil(() => tokenReady);

        if (string.IsNullOrEmpty(attestToken))
        {
            FireFailed("Failed to get attestation token from Oculus SDK.");
            yield break;
        }

        // ─── POST /api/authenticate/attestation/mothershipAuth ────────────────

        string mothershipBody = $"{{\"UserId\":\"{userId}\",\"AttestationToken\":\"{EscapeJson(attestToken)}\"}}";

        // Pass device model in header so server can log it
        var headers = new Dictionary<string, string>
        {
            { "X-Device-Model", SystemInfo.deviceModel }
        };

        yield return PostJson(
            "/api/authenticate/attestation/mothershipAuth",
            mothershipBody,
            headers,
            (code, responseBody) =>
            {
                if (code == 200)
                {
                    Debug.Log("[Auth] PASSED — org: " + orgScopedId);
                    OnAuthPassed?.Invoke(orgScopedId);
                }
                else
                {
                    BanResponse ban = JsonUtility.FromJson<BanResponse>(responseBody);
                    FireFailed(ban?.BanMessage ?? responseBody);
                }
            }
        );
    }

    // ─── Photon Auth ──────────────────────────────────────────────────────────

    public static void LogPhotonAuth(string metaUser, string oculusId, string playfabId, string orgScopedId, int timeTook, string method = "GET")
    {
        if (_instance == null) return;
        _instance.StartCoroutine(_instance.PostPhotonAuth(metaUser, oculusId, playfabId, orgScopedId, timeTook, method));
    }

    private IEnumerator PostPhotonAuth(string metaUser, string oculusId, string playfabId, string orgScopedId, int timeTook, string method)
    {
        string body = "{"
            + $"\"MetaUser\":\"{EscapeJson(metaUser)}\","
            + $"\"OculusId\":\"{EscapeJson(oculusId)}\","
            + $"\"PlayFabId\":\"{EscapeJson(playfabId)}\","
            + $"\"OrgScopedId\":\"{EscapeJson(orgScopedId)}\","
            + $"\"Method\":\"{method}\","
            + $"\"TimeTook\":{timeTook}"
            + "}";

        yield return PostJson("/api/photon-auth", body, null, (code, resp) =>
        {
            if (code != 200) Debug.LogWarning("[Auth] Photon webhook failed: " + resp);
        });
    }

    // ─── HTTP Helper ──────────────────────────────────────────────────────────

    private IEnumerator PostJson(string path, string jsonBody, Dictionary<string, string> extraHeaders, Action<long, string> callback)
    {
        string url = settings.ServerUrl.TrimEnd('/') + path;
        byte[] bytes = Encoding.UTF8.GetBytes(jsonBody);

        using UnityWebRequest req = new UnityWebRequest(url, "POST");
        req.uploadHandler   = new UploadHandlerRaw(bytes);
        req.downloadHandler = new DownloadHandlerBuffer();
        req.SetRequestHeader("Content-Type", "application/json");

        if (extraHeaders != null)
            foreach (var kv in extraHeaders)
                req.SetRequestHeader(kv.Key, kv.Value);

        yield return req.SendWebRequest();

        callback?.Invoke(req.responseCode, req.downloadHandler.text);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static void FireFailed(string reason)
    {
        Debug.LogWarning("[Auth] FAILED: " + reason);
        OnAuthFailed?.Invoke(reason);
    }

    private static string EscapeJson(string s) =>
        (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");

    // ─── Response Shapes ──────────────────────────────────────────────────────

    [Serializable] private class GetNonceResponse
    {
        public string challenge_nonce;
        public string org_scoped_id;
    }

    [Serializable] private class BanResponse
    {
        public string BanMessage;
        public string BanExpirationTime;
    }

    [Serializable] private class ErrorResponse
    {
        public string error;
    }
}
