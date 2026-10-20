# @moonsox/trust

Bot identity for the open web. A bot gets an Ed25519 key, registers it on
[Moonsox Trust](https://trust.moonsox.com), and signs its HTTP requests
([Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/) / RFC 9421).
A site checks the signature and reads the bot's registry-signed card: who it is, and whether it is bonded.

Six functions. Zero dependencies. Node 18.17+, Deno, Bun, Cloudflare Workers and current browsers (WebCrypto).

## Protect your keys: the backup key is the account

Your bot has two keys:

- **The signing key** runs on the bot and signs requests. It is a day-to-day working key.
- **The backup key** (recovery key) never runs on the bot. Keep it offline: paper, a USB stick, or a password manager.
  Whoever holds the backup key controls the bot, and it is the only thing that can replace a lost or stolen signing key.
  Only its hash is sent at registration, and it can only be set when the bot is first registered.

Make both when you create the bot. If you lose both keys, the bot can't be recovered: register a new one.
Disputed ownership freezes the bot and goes to a review panel, which decides.

This package never sends or logs a private key.

## Install

```sh
npm install @moonsox/trust
```

## Bot side

```js
import { generateKeys, register, signRequest } from '@moonsox/trust';

// Once, when you create the bot.
const keys = await generateKeys({ recovery: true });
// keys.privateKeyPem          -> your bot's secret store
// keys.recovery.privateKeyPem -> OFFLINE now. Do not keep it on the bot.

const { botId } = await register(keys.publicKeyPem, {
  username: 'my_bot',                                // optional
  recoveryKeyHash: keys.recovery.recoveryKeyHash,    // commits your backup key (first registration only)
});

// Every request.
const body = JSON.stringify({ q: 'hello' });
const headers = await signRequest(
  { method: 'POST', url: 'https://example.com/api/search', body },
  { botId, privateKeyPem: keys.privateKeyPem },
);
await fetch('https://example.com/api/search', {
  method: 'POST',
  headers: { ...headers, 'content-type': 'application/json' },
  body, // send exactly the bytes you signed
});
```

`register` is idempotent: the same key always returns the same `botId` (`created: false` after the first time).
Errors throw `MoonsoxError` with `status` and `error` (for example `username_taken`, `name_not_allowed`, `rate_limited`).

`signRequest` covers the method, host, path and the `Signature-Agent` header, plus a `Content-Digest`
(RFC 9530, SHA-256) of the body when there is one. Signatures are valid for 5 minutes.

## Site side

```js
import { verifyRequest } from '@moonsox/trust';

const r = await verifyRequest({ method: req.method, url: fullUrl, headers: req.headers, body: rawBody });
if (r.ok && r.card?.bonded) {
  // a registered Moonsox bot signed this request, and it is bonded
}
```

- `r.ok === true` means only "this bot's key signed this request". It does not mean the bot is in good standing.
- `r.card` is the bot's standing: `botId`, `username`, `bonded`, `bondStatus`, amounts and timestamps.
  `card: null` means standing is unknown right now (the card could not be fetched), not that it is bad.
- `r.bodyCovered` tells you whether the body was inside the signature. Pass the raw body bytes you received.
- Whether to require `bonded` is your one-line decision.
- On failure you get `{ ok: false, reason }`. **Treat any reason you don't recognise as "not ok".**

Reasons: `missing_headers`, `bad_signature_input`, `bad_tag`, `expired`, `not_yet_valid`, `unknown_agent`,
`key_not_found`, `keyid_mismatch`, `bad_signature`, `card_unavailable`, `card_bad_hash`, `card_bad_signature`,
`card_unknown_issuer`, `card_stale`, `digest_mismatch`, `body_missing`, `network`.

Only keys published by `trust.moonsox.com` are accepted; a `Signature-Agent` pointing anywhere else is refused (`unknown_agent`).

### Cards

```js
import { getCard, verifyCard } from '@moonsox/trust';

const c = await getCard('my_bot');        // or a bot_... id; verified before it is returned
if (c.ok) console.log(c.summary.bonded);

const again = await verifyCard(c.card);   // offline re-check of a card you kept (default max age: the card's own TTL, 24 h)
```

Cards are signed by the Moonsox registry. The registry key is pinned in this package, so `verifyCard`
works offline. A future registry key is accepted only if it is endorsed by the pinned one.

## API

| Function | Returns |
|---|---|
| `generateKeys(opts?: { recovery?: boolean })` | `{ publicKeyPem, privateKeyPem, recovery?: { publicKeyPem, privateKeyPem, recoveryKeyHash } }` |
| `register(publicKeyPem, profile?: { displayName?, username?, recoveryKeyHash? })` | `{ botId, username, created, recoveryKeySet, raw }` |
| `signRequest({ method, url, body? }, { botId, privateKeyPem })` | headers: `Signature-Agent`, `Signature-Input`, `Signature` (+ `Content-Digest`) |
| `verifyRequest({ method, url, headers, body? })` | `{ ok: true, botId, keyid, created, expires, bodyCovered, card }` or `{ ok: false, reason }` |
| `getCard(botIdOrUsername)` | `{ ok: true, summary, card }` or `{ ok: false, reason }` |
| `verifyCard(card, opts?: { maxAgeSec? })` | `{ ok: true, summary, card }` or `{ ok: false, reason }` |

All functions are async. Verification functions never throw on a failed check; they throw only on bad arguments.
Keys are standard SPKI / PKCS#8 PEM and work with any Ed25519 library.

## Stability

1.x never breaks: no function is removed, renamed or re-typed, no argument becomes required, and results only gain fields.
The package talks only to `https://trust.moonsox.com/sdk/v1/`, an API namespace that is frozen for as long as 1.x is supported.

## Licence

MIT
