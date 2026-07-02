using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace CerberusAuth.Client
{
    /// <summary>Construction-time knobs for <see cref="CerberusClient"/>.</summary>
    public sealed class CerberusClientOptions
    {
        /// <summary>Replaces the default HttpClient (15 second timeout).</summary>
        public HttpClient? HttpClient { get; set; }

        /// <summary>
        /// Additional pinned verification keys (base64 Ed25519), for the
        /// overlap window of a key rotation: ship a release pinning both the
        /// old and the new key, rotate server-side, drop the old pin in the
        /// release after. Responses verifying under any pinned key are
        /// accepted; the envelope's key_id picks the right one.
        /// </summary>
        public IReadOnlyList<string>? ExtraPublicKeys { get; set; }
    }

    /// <summary>
    /// Client for the CerberusAuth license protocol. It performs the
    /// verification sequence every client must do before trusting an answer:
    /// generate a nonce and timestamp, POST, verify the Ed25519 signature
    /// over the exact payload bytes, only then parse, check the nonce echo,
    /// hand over the verdict.
    ///
    /// A signed "no" is a real answer: Validate and Redeem return a
    /// <see cref="Verdict"/> with Valid == false when the server rejects the
    /// license. Exceptions mean no trustworthy answer exists at all
    /// (network failure, non-200, bad signature, replayed nonce): fail
    /// closed, keep the app locked, retry later.
    ///
    /// Machines with a wrong clock still validate: a signed stale_timestamp
    /// verdict teaches the client the server clock and it retries once.
    ///
    /// Thread-safe; create one instance per application and reuse it.
    /// </summary>
    public sealed class CerberusClient
    {
        private const int Ed25519KeySize = 32;

        private readonly HttpClient _http;
        private readonly string _baseUrl;
        private readonly string _appId;
        private readonly Dictionary<string, byte[]> _keys; // key id -> public key
        private long _clockOffsetSeconds;

        /// <param name="baseUrl">Server root, like https://auth.example.com.</param>
        /// <param name="appId">The application UUID.</param>
        /// <param name="publicKey">The app's base64 Ed25519 verification key, pinned at build time.</param>
        /// <param name="options">Optional knobs; see <see cref="CerberusClientOptions"/>.</param>
        public CerberusClient(string baseUrl, string appId, string publicKey, CerberusClientOptions? options = null)
        {
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || uri.Host.Length == 0)
                throw new ArgumentException("base URL must be absolute, like https://auth.example.com", nameof(baseUrl));
            if (string.IsNullOrEmpty(appId))
                throw new ArgumentException("app ID is required", nameof(appId));

            _baseUrl = baseUrl.TrimEnd('/');
            _appId = appId;
            _http = options?.HttpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };

            _keys = new Dictionary<string, byte[]>();
            AddKey(publicKey, nameof(publicKey));
            if (options?.ExtraPublicKeys != null)
                foreach (var k in options.ExtraPublicKeys)
                    AddKey(k, nameof(options.ExtraPublicKeys));
        }

        private void AddKey(string base64, string paramName)
        {
            byte[] pub;
            try { pub = Convert.FromBase64String(base64); }
            catch (FormatException) { throw new ArgumentException("public key must be a base64 32-byte Ed25519 key", paramName); }
            if (pub.Length != Ed25519KeySize)
                throw new ArgumentException("public key must be a base64 32-byte Ed25519 key", paramName);
            _keys[KeyId(pub)] = pub;
        }

        /// <summary>
        /// Asks whether the license is good for this device right now. hwid
        /// is any stable device identifier you choose; the server only ever
        /// sees and stores its hash.
        /// </summary>
        public Task<Verdict> ValidateAsync(string licenseKey, string hwid, CancellationToken ct = default)
            => CallAsync("/v1/client/validate", licenseKey, hwid, ct);

        /// <summary>
        /// Activates an issued license on this device: binds the hwid and
        /// starts the expiry clock. Redeeming an already-active license with
        /// the same hwid succeeds, so retrying after a lost response is safe.
        /// </summary>
        public Task<Verdict> RedeemAsync(string licenseKey, string hwid, CancellationToken ct = default)
            => CallAsync("/v1/client/redeem", licenseKey, hwid, ct);

        /// <summary>
        /// Re-verifies a previously persisted <see cref="Verdict.Envelope"/>:
        /// same signature and version checks as a live call, minus the nonce
        /// echo, which only makes sense for a response just requested. The
        /// caller owns freshness: check <see cref="Verdict.ServerTime"/>
        /// against the grace period the app allows. Never feed this anything
        /// but envelopes this program stored itself.
        /// </summary>
        public Verdict VerifyStored(byte[] envelopeJson) => Verify(envelopeJson, wantNonce: null);

        private async Task<Verdict> CallAsync(string path, string licenseKey, string hwid, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(licenseKey)) throw new ArgumentException("license key is required", nameof(licenseKey));
            if (string.IsNullOrEmpty(hwid)) throw new ArgumentException("hwid is required", nameof(hwid));

            var v = await OnceAsync(path, licenseKey, hwid, ct).ConfigureAwait(false);
            if (v.Valid || v.Reason != Reasons.StaleTimestamp)
                return v;

            // Our clock is off by more than the server tolerates. The
            // rejection is signed and bound to our nonce, so its server time
            // is trustworthy: learn the offset and retry once. Safe for
            // redeem too; the server's skew check runs before any state
            // change.
            var offset = v.ServerTime.ToUnixTimeSeconds() - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Interlocked.Exchange(ref _clockOffsetSeconds, offset);
            return await OnceAsync(path, licenseKey, hwid, ct).ConfigureAwait(false);
        }

        private async Task<Verdict> OnceAsync(string path, string licenseKey, string hwid, CancellationToken ct)
        {
            var nonce = NewNonce();
            var body = JsonSerializer.SerializeToUtf8Bytes(new RequestDto
            {
                AppId = _appId,
                LicenseKey = licenseKey,
                Hwid = hwid,
                Nonce = nonce,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + Interlocked.Read(ref _clockOffsetSeconds),
            });

            using var req = new HttpRequestMessage(HttpMethod.Post, _baseUrl + path)
            {
                Content = new ByteArrayContent(body),
            };
            req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var raw = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

            if ((int)resp.StatusCode != 200)
                throw new CerberusTransportException((int)resp.StatusCode, ApiMessage(raw));

            return Verify(raw, nonce);
        }

        /// <summary>
        /// The mandatory sequence: signature over the exact payload bytes
        /// first, JSON second, then the echo checks.
        /// </summary>
        private Verdict Verify(byte[] envelopeJson, string? wantNonce)
        {
            EnvelopeDto env;
            try
            {
                env = JsonSerializer.Deserialize<EnvelopeDto>(envelopeJson)
                    ?? throw new CerberusProtocolException("malformed envelope");
            }
            catch (JsonException e)
            {
                throw new CerberusProtocolException("malformed envelope: " + e.Message);
            }

            if (env.Alg != "ed25519")
                throw new CerberusProtocolException($"unsupported signature algorithm \"{env.Alg}\"");

            byte[] payload, sig;
            try
            {
                payload = Convert.FromBase64String(env.Payload ?? "");
                sig = Convert.FromBase64String(env.Signature ?? "");
            }
            catch (FormatException)
            {
                throw new CerberusSignatureException();
            }
            if (sig.Length != Ed25519.SignatureSize || !VerifyAgainstPinnedKeys(env.KeyId ?? "", payload, sig))
                throw new CerberusSignatureException();

            PayloadDto p;
            try
            {
                p = JsonSerializer.Deserialize<PayloadDto>(payload)
                    ?? throw new CerberusProtocolException("empty verified payload");
            }
            catch (JsonException e)
            {
                throw new CerberusProtocolException("parse verified payload: " + e.Message);
            }

            if (p.V != 1)
                throw new CerberusProtocolException($"unsupported payload version {p.V}, update the SDK");
            if (p.AppId != _appId)
                throw new CerberusProtocolException($"response is about app {p.AppId}, expected {_appId}");
            if (wantNonce != null && p.Nonce != wantNonce)
                throw new CerberusReplayException();

            return new Verdict
            {
                Valid = p.Valid,
                Reason = p.Reason ?? "",
                LicenseId = p.LicenseId ?? "",
                Tier = p.Tier ?? "",
                ExpiresAt = p.ExpiresAt > 0 ? DateTimeOffset.FromUnixTimeSeconds(p.ExpiresAt) : (DateTimeOffset?)null,
                ServerTime = DateTimeOffset.FromUnixTimeSeconds(p.ServerTs),
                KeyId = env.KeyId ?? "",
                Envelope = envelopeJson,
            };
        }

        private bool VerifyAgainstPinnedKeys(string keyId, byte[] payload, byte[] sig)
        {
            // The envelope's key_id picks the pinned key; if it names none of
            // ours, fall back to trying each. Either way only a signature
            // under a pinned key passes.
            if (_keys.TryGetValue(keyId, out var pub))
                return Ed25519.Verify(sig, 0, pub, 0, payload, 0, payload.Length);
            foreach (var k in _keys.Values)
                if (Ed25519.Verify(sig, 0, k, 0, payload, 0, payload.Length))
                    return true;
            return false;
        }

        /// <summary>First 8 bytes of SHA-256 over the raw key, hex: the server's fingerprint.</summary>
        private static string KeyId(byte[] pub)
        {
            using var sha = SHA256.Create();
            var sum = sha.ComputeHash(pub);
            var sb = new StringBuilder(16);
            for (var i = 0; i < 8; i++) sb.Append(sum[i].ToString("x2"));
            return sb.ToString();
        }

        private static string NewNonce()
        {
            var b = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(b);
            var sb = new StringBuilder(32);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        private static string ApiMessage(byte[] body)
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String)
                    return e.GetString() ?? "";
            }
            catch (JsonException) { }
            var s = Encoding.UTF8.GetString(body).Trim();
            return s.Length > 200 ? s.Substring(0, 200) : s;
        }

        private sealed class RequestDto
        {
            [JsonPropertyName("app_id")] public string AppId { get; set; } = "";
            [JsonPropertyName("license_key")] public string LicenseKey { get; set; } = "";
            [JsonPropertyName("hwid")] public string Hwid { get; set; } = "";
            [JsonPropertyName("nonce")] public string Nonce { get; set; } = "";
            [JsonPropertyName("timestamp")] public long Timestamp { get; set; }
        }

        private sealed class EnvelopeDto
        {
            [JsonPropertyName("alg")] public string? Alg { get; set; }
            [JsonPropertyName("key_id")] public string? KeyId { get; set; }
            [JsonPropertyName("payload")] public string? Payload { get; set; }
            [JsonPropertyName("signature")] public string? Signature { get; set; }
        }

        private sealed class PayloadDto
        {
            [JsonPropertyName("v")] public int V { get; set; }
            [JsonPropertyName("valid")] public bool Valid { get; set; }
            [JsonPropertyName("reason")] public string? Reason { get; set; }
            [JsonPropertyName("app_id")] public string? AppId { get; set; }
            [JsonPropertyName("license_id")] public string? LicenseId { get; set; }
            [JsonPropertyName("tier")] public string? Tier { get; set; }
            [JsonPropertyName("expires_at")] public long ExpiresAt { get; set; }
            [JsonPropertyName("hwid")] public string? Hwid { get; set; }
            [JsonPropertyName("nonce")] public string? Nonce { get; set; }
            [JsonPropertyName("client_ts")] public long ClientTs { get; set; }
            [JsonPropertyName("server_ts")] public long ServerTs { get; set; }
        }
    }
}
