using System;

namespace CerberusAuth.Client
{
    /// <summary>
    /// Stable failure reason strings carried in signed verdicts. Part of the
    /// server's API contract; compare against these, not against prose.
    /// </summary>
    public static class Reasons
    {
        /// <summary>The key does not exist for this app or is malformed.</summary>
        public const string InvalidKey = "invalid_key";
        /// <summary>The key exists but was never activated; redeem first.</summary>
        public const string NotRedeemed = "not_redeemed";
        /// <summary>The license was banned by an admin.</summary>
        public const string Banned = "banned";
        /// <summary>The license has run out.</summary>
        public const string Expired = "expired";
        /// <summary>The license is bound to a different device.</summary>
        public const string HwidMismatch = "hwid_mismatch";
        /// <summary>
        /// The request timestamp fell outside the server's accepted skew. The
        /// client corrects its clock offset from the signed response and
        /// retries once on its own; callers only see this when the retry was
        /// rejected too.
        /// </summary>
        public const string StaleTimestamp = "stale_timestamp";
    }

    /// <summary>
    /// A verified license decision: the signature checked out and, for live
    /// calls, the nonce echo matched. <c>Valid == false</c> is an
    /// authoritative server-signed denial, not an error; errors (no
    /// trustworthy answer at all) surface as exceptions instead.
    /// </summary>
    public sealed class Verdict
    {
        public bool Valid { get; internal set; }

        /// <summary>Set when <see cref="Valid"/> is false; see <see cref="Reasons"/>.</summary>
        public string Reason { get; internal set; } = "";

        public string LicenseId { get; internal set; } = "";
        public string Tier { get; internal set; } = "";

        /// <summary>Expiry instant; null means the license is perpetual.</summary>
        public DateTimeOffset? ExpiresAt { get; internal set; }

        /// <summary>Server clock at signing time; judge cached verdict age with it.</summary>
        public DateTimeOffset ServerTime { get; internal set; }

        /// <summary>Fingerprint of the signing key (relevant across rotations).</summary>
        public string KeyId { get; internal set; } = "";

        /// <summary>
        /// The raw signed response exactly as received. Persist it for an
        /// offline grace period: <see cref="CerberusClient.VerifyStored"/>
        /// re-checks the signature at load time, so a tampered cache file
        /// fails closed.
        /// </summary>
        public byte[] Envelope { get; internal set; } = Array.Empty<byte>();
    }

    /// <summary>Base type for every failure this SDK throws.</summary>
    public class CerberusException : Exception
    {
        public CerberusException(string message) : base(message) { }
    }

    /// <summary>
    /// The response failed Ed25519 verification: forged, tampered with, or
    /// signed by a key other than the pinned ones. Treat the license as
    /// invalid; never retry with relaxed checks.
    /// </summary>
    public sealed class CerberusSignatureException : CerberusException
    {
        public CerberusSignatureException()
            : base("signature verification failed: response is forged, tampered with, or signed by an unpinned key") { }
    }

    /// <summary>
    /// The signature was fine but the echoed nonce is not the one just sent:
    /// a recorded response is being replayed. Treat as invalid.
    /// </summary>
    public sealed class CerberusReplayException : CerberusException
    {
        public CerberusReplayException()
            : base("nonce mismatch: response replayed or answers a different request") { }
    }

    /// <summary>
    /// An unsigned transport-level failure (any HTTP status other than 200).
    /// Never a license verdict: verdicts, including denials, arrive signed
    /// with status 200. Fail closed and retry later.
    /// </summary>
    public sealed class CerberusTransportException : CerberusException
    {
        public int StatusCode { get; }

        public CerberusTransportException(int statusCode, string apiMessage)
            : base(apiMessage.Length == 0
                ? $"server returned HTTP {statusCode}"
                : $"server returned HTTP {statusCode}: {apiMessage}")
        {
            StatusCode = statusCode;
        }
    }

    /// <summary>
    /// The response verified but violates the protocol: unsupported payload
    /// version or algorithm, malformed JSON, or a verdict about a different
    /// application.
    /// </summary>
    public sealed class CerberusProtocolException : CerberusException
    {
        public CerberusProtocolException(string message) : base(message) { }
    }
}
