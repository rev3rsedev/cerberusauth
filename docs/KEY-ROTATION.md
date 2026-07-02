# Key rotation

CerberusAuth has two kinds of keys with two very different blast radii:

- **App signing keys**: one Ed25519 keypair per application signs verdicts.
  Clients pin the public half. Rotating one is routine.
- **The master key** (`CERBERUS_MASTER_KEY`): encrypts every app's private
  signing key at rest and peppers admin email hashes. Rotating it is an
  incident response.

## Rotating an app signing key (routine)

An app can hold several keys; exactly one is active and signs. Retired
keys stay listed on `GET /v1/client/apps/{id}/pubkey` so clients that pin
them keep verifying old responses while they migrate.

1. Ship a client release that pins both the current and the upcoming key.
   With the Go SDK: `client.New(url, appID, newKey,
   client.WithExtraPublicKeys(oldKey))`. There is no upcoming key yet at
   this point, so in practice: rotate first on a staging app, or accept
   the short window in step 3.
2. Rotate: `POST /v1/admin/apps/{id}/rotate-key`. The response carries the
   new public key. From this instant every verdict is signed by it.
3. Clients pinning only the old key now fail closed (signature mismatch).
   That is pinning working as designed, and why step 1 ships first.
4. Once old releases are gone, drop the old pin from the client.

Order matters: pin-both releases must reach users before the rotation
flips signing, otherwise those users are locked out until they update.

## Master key leaked (incident)

Assume the attacker has a database copy: they can decrypt every app
signing key and forge verdicts for existing apps, offline. The goal is to
make everything they hold worthless.

1. Generate a replacement: `cerberusd genkey`.
2. Re-encrypt all app signing keys under the new master key:

   ```sh
   cerberusd rekey -old <leaked key> -new <new key>
   ```

   Safe to rerun after a partial failure; already-migrated rows are
   skipped.
3. Set `CERBERUS_MASTER_KEY` to the new key everywhere and restart.
4. Recreate admin users with `create-admin`. Email hashes are peppered by
   a key derived from the master key, and plaintext emails are never
   stored, so existing admin rows cannot be migrated; logins against them
   stop working after the swap. Existing admin tokens die with them.
5. Rotate every app's signing key (`POST /v1/admin/apps/{id}/rotate-key`).
   The attacker had the old ciphertexts and the old master key, so treat
   every old signing key as public.
6. Ship client updates pinning the new public keys. Until users update,
   their clients still trust a key the attacker can sign with; that
   exposure only closes client-side.

Step 6 is the honest part: a leaked master key cannot be fully recovered
from server-side alone. Pinning moves trust into the shipped binary, so
replacing trust means shipping.
