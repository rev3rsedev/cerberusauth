# CerberusAuth.Client (.NET)

C# SDK for the CerberusAuth client protocol. Targets netstandard2.1
(Unity, Mono) and net8.0. One dependency: BouncyCastle, because the BCL
has no Ed25519.

```csharp
using CerberusAuth.Client;

var client = new CerberusClient(
    "https://auth.example.com",
    "6c9028f8-11a1-4e5e-9f30-1d2c3b4a5968",       // your app's UUID
    "vGm0Hgu3v1n0Ka7SwzW9DlFOMFY2M3lQxN4mB2kQzUM=" // pinned at build time
);

try
{
    // First run: RedeemAsync. Later startups: ValidateAsync.
    var v = await client.ValidateAsync(licenseKey, hwid);
    if (!v.Valid)
    {
        // Signed, authoritative denial. v.Reason is one of the Reasons
        // constants: not_redeemed, banned, expired, hwid_mismatch, ...
        return;
    }
    // Licensed: v.Tier, v.ExpiresAt (null = perpetual).
}
catch (CerberusException)
{
    // No trustworthy answer: offline, forged response, replayed nonce.
    // Fail closed, keep the app locked, retry later.
}
```

The SDK does the whole mandatory sequence for you: random nonce, Ed25519
verification over the exact payload bytes before parsing, nonce echo
check, clock-skew self-correction (a signed stale_timestamp verdict
teaches it the server clock; it retries once).

A signed "no" comes back as a `Verdict`, never an exception. Exceptions
(`CerberusSignatureException`, `CerberusReplayException`,
`CerberusTransportException`, `CerberusProtocolException`) all mean the
same thing operationally: no trustworthy answer exists, fail closed.

Key rotation: pin several keys during the overlap window via
`CerberusClientOptions.ExtraPublicKeys`; the envelope's `key_id` selects
the right one. Flow and runbook: [docs/KEY-ROTATION.md](../../docs/KEY-ROTATION.md).

Offline grace period: persist `Verdict.Envelope` after a valid answer;
when the server is unreachable, load it, re-verify with
`client.VerifyStored(bytes)` and accept it if `ServerTime` is recent
enough for your taste. A signed denial always deletes the cache.

Tests include a vector signed by the Go implementation, so the two SDKs
cannot drift apart silently:

```sh
dotnet test sdk/csharp/CerberusAuth.Client.Tests
```
