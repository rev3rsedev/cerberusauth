using System;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace CerberusAuth.Client.Tests;

/// <summary>
/// A localhost fake of the client endpoints, signing with a BouncyCastle
/// Ed25519 key. Mirrors the wire protocol, not the server internals.
/// </summary>
internal sealed class FakeServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly Func<JsonElement, string, object> _respond; // (request, path) -> payload object
    public readonly byte[] PublicKey = new byte[32];
    private readonly byte[] _priv = new byte[32];
    public readonly ConcurrentQueue<(string Path, JsonElement Body)> Requests = new();
    public string Url { get; }

    public FakeServer(Func<JsonElement, string, object> respond, int? seed = null)
    {
        _respond = respond;
        if (seed is int s)
            for (var i = 0; i < 32; i++) _priv[i] = (byte)(s + i);
        else
            RandomNumberGenerator.Fill(_priv);
        Ed25519.GeneratePublicKey(_priv, 0, PublicKey, 0);

        var port = FreePort();
        Url = $"http://127.0.0.1:{port}";
        _listener.Prefixes.Add(Url + "/");
        _listener.Start();
        _ = Task.Run(Loop);
    }

    public string PublicKeyB64 => Convert.ToBase64String(PublicKey);

    public string KeyId
    {
        get
        {
            var sum = SHA256.HashData(PublicKey);
            var sb = new StringBuilder(16);
            for (var i = 0; i < 8; i++) sb.Append(sum[i].ToString("x2"));
            return sb.ToString();
        }
    }

    public byte[] SignEnvelope(object payload, string? alg = null, string? keyId = null)
    {
        var raw = JsonSerializer.SerializeToUtf8Bytes(payload);
        var sig = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(_priv, 0, raw, 0, raw.Length, sig, 0);
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = alg ?? "ed25519",
            key_id = keyId ?? KeyId,
            payload = Convert.ToBase64String(raw),
            signature = Convert.ToBase64String(sig),
        });
    }

    private async Task Loop()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch (Exception) { return; } // listener stopped
            using var reader = new System.IO.StreamReader(ctx.Request.InputStream);
            var body = JsonDocument.Parse(await reader.ReadToEndAsync()).RootElement.Clone();
            Requests.Enqueue((ctx.Request.Url!.AbsolutePath, body));

            var payload = _respond(body, ctx.Request.Url!.AbsolutePath);
            byte[] resp;
            if (payload is (int code, string msg))
            {
                ctx.Response.StatusCode = code;
                resp = JsonSerializer.SerializeToUtf8Bytes(new { error = msg });
            }
            else
            {
                resp = SignEnvelope(payload);
            }
            ctx.Response.ContentType = "application/json";
            await ctx.Response.OutputStream.WriteAsync(resp);
            ctx.Response.Close();
        }
    }

    private static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    public void Dispose() => _listener.Stop();
}

public class ClientTests
{
    private const string AppId = "6c9028f8-11a1-4e5e-9f30-1d2c3b4a5968";

    /// <summary>Echo a request back as a valid verdict, like the real server.</summary>
    private static object Ok(JsonElement req) => new
    {
        v = 1,
        valid = true,
        app_id = req.GetProperty("app_id").GetString(),
        license_id = "lic-1",
        tier = "pro",
        hwid = req.GetProperty("hwid").GetString(),
        nonce = req.GetProperty("nonce").GetString(),
        client_ts = req.GetProperty("timestamp").GetInt64(),
        server_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    };

    private static object Denied(JsonElement req, string reason) => new
    {
        v = 1,
        valid = false,
        reason,
        app_id = req.GetProperty("app_id").GetString(),
        nonce = req.GetProperty("nonce").GetString(),
        client_ts = req.GetProperty("timestamp").GetInt64(),
        server_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    };

    private static CerberusClient NewClient(FakeServer s, CerberusClientOptions? opts = null)
        => new(s.Url, AppId, s.PublicKeyB64, opts);

    [Fact]
    public async Task ValidateHappyPath()
    {
        using var s = new FakeServer((req, _) => Ok(req));
        var v = await NewClient(s).ValidateAsync("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "device-1");

        Assert.True(v.Valid);
        Assert.Equal("", v.Reason);
        Assert.Equal("lic-1", v.LicenseId);
        Assert.Equal("pro", v.Tier);
        Assert.Null(v.ExpiresAt); // perpetual
        Assert.Equal(s.KeyId, v.KeyId);
        Assert.NotEmpty(v.Envelope);

        Assert.True(s.Requests.TryDequeue(out var got));
        Assert.Equal("/v1/client/validate", got.Path);
        Assert.Equal(AppId, got.Body.GetProperty("app_id").GetString());
        Assert.Equal(32, got.Body.GetProperty("nonce").GetString()!.Length);
    }

    [Fact]
    public async Task RedeemUsesRedeemPath()
    {
        using var s = new FakeServer((req, _) => Ok(req));
        await NewClient(s).RedeemAsync("KEY", "device-1");
        Assert.True(s.Requests.TryDequeue(out var got));
        Assert.Equal("/v1/client/redeem", got.Path);
    }

    [Fact]
    public async Task SignedDenialIsNotAnException()
    {
        using var s = new FakeServer((req, _) => Denied(req, Reasons.Banned));
        var v = await NewClient(s).ValidateAsync("KEY", "device-1");
        Assert.False(v.Valid);
        Assert.Equal(Reasons.Banned, v.Reason);
    }

    [Fact]
    public async Task ForgedSignatureRejected()
    {
        using var signer = new FakeServer((req, _) => Ok(req));
        using var pinnedOther = new FakeServer((req, _) => Ok(req));
        // Client pins pinnedOther's key but talks to signer.
        var c = new CerberusClient(signer.Url, AppId, pinnedOther.PublicKeyB64);
        await Assert.ThrowsAsync<CerberusSignatureException>(() => c.ValidateAsync("KEY", "device-1"));
    }

    [Fact]
    public async Task ReplayedNonceRejected()
    {
        using var s = new FakeServer((req, _) => new
        {
            v = 1,
            valid = true,
            app_id = req.GetProperty("app_id").GetString(),
            nonce = "aaaaaaaaaaaaaaaa", // signed fine, not our nonce
            server_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
        await Assert.ThrowsAsync<CerberusReplayException>(() => NewClient(s).ValidateAsync("KEY", "device-1"));
    }

    [Fact]
    public async Task WrongAppRejected()
    {
        using var s = new FakeServer((req, _) => new
        {
            v = 1,
            valid = true,
            app_id = "someone-elses-app",
            nonce = req.GetProperty("nonce").GetString(),
            server_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
        var e = await Assert.ThrowsAsync<CerberusProtocolException>(() => NewClient(s).ValidateAsync("KEY", "device-1"));
        Assert.Contains("about app", e.Message);
    }

    [Fact]
    public async Task TransportErrorFailsClosed()
    {
        using var s = new FakeServer((_, _) => (404, "application not found"));
        var e = await Assert.ThrowsAsync<CerberusTransportException>(() => NewClient(s).ValidateAsync("KEY", "device-1"));
        Assert.Equal(404, e.StatusCode);
        Assert.Contains("application not found", e.Message);
    }

    [Fact]
    public async Task UnsupportedVersionRejected()
    {
        using var s = new FakeServer((req, _) => new
        {
            v = 2,
            valid = true,
            app_id = req.GetProperty("app_id").GetString(),
            nonce = req.GetProperty("nonce").GetString(),
            server_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
        var e = await Assert.ThrowsAsync<CerberusProtocolException>(() => NewClient(s).ValidateAsync("KEY", "device-1"));
        Assert.Contains("unsupported payload version", e.Message);
    }

    [Fact]
    public async Task SkewCorrectionRetriesOnce()
    {
        // Server clock an hour ahead; reject drift over 5 minutes.
        var serverNow = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        using var s = new FakeServer((req, _) =>
        {
            var drift = Math.Abs(serverNow - req.GetProperty("timestamp").GetInt64());
            return drift > 300
                ? new
                {
                    v = 1,
                    valid = false,
                    reason = Reasons.StaleTimestamp,
                    app_id = req.GetProperty("app_id").GetString(),
                    nonce = req.GetProperty("nonce").GetString(),
                    server_ts = serverNow,
                }
                : Ok(req);
        });

        var c = NewClient(s);
        var v = await c.ValidateAsync("KEY", "device-1");
        Assert.True(v.Valid);
        Assert.Equal(2, s.Requests.Count); // original + corrected retry

        // The learned offset sticks: next call lands on the first try.
        await c.ValidateAsync("KEY", "device-1");
        Assert.Equal(3, s.Requests.Count);
    }

    [Fact]
    public async Task ExtraPinnedKeysAcceptRotatedSigner()
    {
        using var newSigner = new FakeServer((req, _) => Ok(req));
        using var oldSigner = new FakeServer((req, _) => Ok(req));
        var c = new CerberusClient(newSigner.Url, AppId, oldSigner.PublicKeyB64, new CerberusClientOptions
        {
            ExtraPublicKeys = new[] { newSigner.PublicKeyB64 },
        });
        var v = await c.ValidateAsync("KEY", "device-1");
        Assert.True(v.Valid);
        Assert.Equal(newSigner.KeyId, v.KeyId);
    }

    [Fact]
    public async Task VerifyStoredRoundTripAndTamper()
    {
        using var s = new FakeServer((req, _) => Ok(req));
        var c = NewClient(s);
        var live = await c.ValidateAsync("KEY", "device-1");

        var stored = c.VerifyStored(live.Envelope);
        Assert.True(stored.Valid);
        Assert.Equal(live.LicenseId, stored.LicenseId);

        // Flip one payload byte: the cache fails closed.
        using var doc = JsonDocument.Parse(live.Envelope);
        var payload = Convert.FromBase64String(doc.RootElement.GetProperty("payload").GetString()!);
        payload[0] ^= 0xFF;
        var tampered = JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "ed25519",
            key_id = doc.RootElement.GetProperty("key_id").GetString(),
            payload = Convert.ToBase64String(payload),
            signature = doc.RootElement.GetProperty("signature").GetString(),
        });
        Assert.Throws<CerberusSignatureException>(() => c.VerifyStored(tampered));
    }

    // Signed by the Go implementation (.dev/vector). If this verifies, both
    // SDKs and the server agree on the protocol byte-for-byte.
    private const string GoPubKey = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=";
    private const string GoEnvelope = "{\"alg\":\"ed25519\",\"key_id\":\"65b60673d6ed884b\",\"payload\":\"eyJ2IjoxLCJ2YWxpZCI6dHJ1ZSwiYXBwX2lkIjoiNmM5MDI4ZjgtMTFhMS00ZTVlLTlmMzAtMWQyYzNiNGE1OTY4IiwibGljZW5zZV9pZCI6IjBlOGRjYzI2LTcxNTItNGM5OS05M2I2LTJiNDdjZTdkMGIzYSIsInRpZXIiOiJwcm8iLCJleHBpcmVzX2F0IjoxNzgyMDAwMDAwLCJod2lkIjoiZGV2aWNlLXZlY3RvciIsIm5vbmNlIjoiMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYiLCJjbGllbnRfdHMiOjE3NTE0NjkwMDAsInNlcnZlcl90cyI6MTc1MTQ2OTAwMX0=\",\"signature\":\"7rTG2sSPrDIANGuTgL9boiX6GsQ2DsqtsF5MVtEM0506AGuSkq7zNkVKOgbuuiI9gsEspvGzaJ9bq3IKKNmNBw==\"}";

    [Fact]
    public void CrossLanguageVectorFromGoVerifies()
    {
        var c = new CerberusClient("http://localhost:1", AppId, GoPubKey);
        var v = c.VerifyStored(Encoding.UTF8.GetBytes(GoEnvelope));

        Assert.True(v.Valid);
        Assert.Equal("0e8dcc26-7152-4c99-93b6-2b47ce7d0b3a", v.LicenseId);
        Assert.Equal("pro", v.Tier);
        Assert.Equal("65b60673d6ed884b", v.KeyId);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1782000000), v.ExpiresAt);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1751469001), v.ServerTime);
    }

    [Fact]
    public void ConstructorRejectsBadInputs()
    {
        Assert.Throws<ArgumentException>(() => new CerberusClient("not a url", AppId, GoPubKey));
        Assert.Throws<ArgumentException>(() => new CerberusClient("http://x", "", GoPubKey));
        Assert.Throws<ArgumentException>(() => new CerberusClient("http://x", AppId, "not-base64!!"));
        Assert.Throws<ArgumentException>(() => new CerberusClient("http://x", AppId, Convert.ToBase64String(new byte[5])));
    }

    [Fact]
    public async Task EmptyArgumentsRejectedLocally()
    {
        var c = new CerberusClient("http://127.0.0.1:1", AppId, GoPubKey);
        await Assert.ThrowsAsync<ArgumentException>(() => c.ValidateAsync("", "device-1"));
        await Assert.ThrowsAsync<ArgumentException>(() => c.ValidateAsync("KEY", ""));
    }
}
