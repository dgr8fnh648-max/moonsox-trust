#!/usr/bin/env node
// @moonsox/trust /sdk/v1 conformance suite: the Trust deploy gate (spec §4.2 item 9).
// Exit 0 = pass, 1 = any check failed.
//
//   node scripts/conformance.mjs [--base https://trust.moonsox.com] [--key-file PATH] [--username NAME] [--sdk PATH]
//
// --base       Trust origin to test (default https://trust.moonsox.com; on moonsox-1 use http://127.0.0.1:43191).
//              The SDK itself only ever calls https://trust.moonsox.com/sdk/v1; this script redirects fetch.
// --key-file   Throwaway conformance bot key (created on first run, chmod 600, reused after so reruns are 200).
// --username   Username for the conformance bot on first registration (default sdk_conformance_<yyyymmdd>).
// --sdk        Path to the built SDK (default ../dist/index.js).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const BASE = (args.base || 'https://trust.moonsox.com').replace(/\/$/, '');
const KEY_FILE = args['key-file'] || path.join(os.homedir(), '.moonsox-sdk-conformance-key.json');
const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const USERNAME = args.username || `sdk_conformance_${today}`;
const SDK_PATH = args.sdk ? path.resolve(args.sdk) : path.join(here, '..', 'dist', 'index.js');
const PROD = 'https://trust.moonsox.com';
const PINNED = 'did:key:z6Mksvo92UP18ArfRs7BJdZNEPXjbPAe2yiw4nN2iJENvNvj';
const GOLDEN_BOT = 'bot_7b208c4edcae2ec289792078'; // a long-lived public card used as the golden card

const realFetch = globalThis.fetch;
globalThis.fetch = (url, init) => realFetch(String(url).startsWith(PROD + '/') ? BASE + String(url).slice(PROD.length) : url, init);
const sdk = await import(pathToFileURL(SDK_PATH).href);

let failed = 0;
const results = [];
async function check(name, fn) {
  try {
    const detail = await fn();
    results.push(`PASS ${name}${detail ? ' (' + detail + ')' : ''}`);
  } catch (e) {
    failed++;
    results.push(`FAIL ${name}: ${e && e.message ? e.message : e}`);
  }
}
function must(cond, msg) { if (!cond) throw new Error(msg); }
async function get(p) {
  const r = await realFetch(BASE + p, { headers: { accept: 'application/json' } });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, headers: r.headers, text, json };
}
async function post(p, body) {
  const r = await realFetch(BASE + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, headers: r.headers, text, json };
}
const kidOf = (pem) => { const j = createPublicKey(pem).export({ format: 'jwk' }); return createHash('sha256').update(JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x })).digest('base64url'); };

// Hand-rolled signer for the legacy / alternative Signature-Agent forms.
function legacySign({ method, url, agentUrl, privateKeyPem }) {
  const u = new URL(url);
  const kid = kidOf(createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' }));
  const agent = `"${agentUrl}"`;
  const created = Math.floor(Date.now() / 1000);
  const params = `("@method" "@authority" "@path" "signature-agent");created=${created};expires=${created + 300};keyid="${kid}";alg="ed25519";nonce="nConf${created}";tag="web-bot-auth"`;
  const base = `"@method": ${method}\n"@authority": ${u.host}\n"@path": ${u.pathname}\n"signature-agent": ${agent}\n"@signature-params": ${params}`;
  return { 'Signature-Agent': agent, 'Signature-Input': `sig=${params}`, Signature: `sig=:${sign(null, Buffer.from(base), createPrivateKey(privateKeyPem)).toString('base64')}:` };
}

// 1. issuer
await check('issuer: pinned root is current, CORS, cache', async () => {
  const r = await get('/sdk/v1/issuer');
  must(r.status === 200, 'status ' + r.status);
  must(r.headers.get('access-control-allow-origin') === '*', 'CORS');
  must(/max-age=3600/.test(r.headers.get('cache-control') || ''), 'cache-control');
  const k = (r.json.keys || []).find((x) => x.didKey === PINNED);
  must(k && k.status === 'current' && typeof k.since === 'string', 'pinned key not current');
  must(r.json.root === PINNED, 'root != pinned');
  must('endorsedBy' in k && !k.endorsedBy, 'root must carry an empty endorsement');
  return `${r.json.keys.length} key(s)`;
});

// 2. golden card (live, by id and by name) + same document as main /v1
await check('golden card: getCard by botId verifies offline against the pinned key', async () => {
  const r = await sdk.getCard(GOLDEN_BOT);
  must(r.ok, JSON.stringify(r));
  must(r.summary.botId === GOLDEN_BOT, 'botId');
  return `bonded=${r.summary.bonded}`;
});
await check('golden card: getCard by username', async () => {
  const card = await get(`/sdk/v1/bots/${GOLDEN_BOT}/card`);
  const name = card.json && card.json.subject && card.json.subject.username;
  must(name, 'golden bot has no username');
  const r = await sdk.getCard(name);
  must(r.ok && r.summary.botId === GOLDEN_BOT, JSON.stringify(r));
});
await check('card: /sdk/v1 card is the same document as main /v1 (modulo mint time)', async () => {
  const [a, b] = await Promise.all([get(`/sdk/v1/bots/${GOLDEN_BOT}/card`), get(`/v1/bots/${GOLDEN_BOT}/card`)]);
  must(a.status === 200 && b.status === 200, `status ${a.status}/${b.status}`);
  must(a.headers.get('access-control-allow-origin') === '*', 'CORS on card');
  const strip = (c) => { const x = structuredClone(c); delete x.bundleHash; delete x.signature; delete x.exportMeta.mintedAt; delete x.bond.asOf; delete x.bond.asOfSlot; if (x.poster) delete x.poster.asOf; return JSON.stringify(Object.keys(x).sort().map((k) => [k, x[k]])); };
  must(strip(a.json) === strip(b.json), 'card documents differ');
  must((await sdk.verifyCard(a.json)).ok && (await sdk.verifyCard(b.json)).ok, 'both verify');
});
await check('card: frozen fields present', async () => {
  const c = (await get(`/sdk/v1/bots/${GOLDEN_BOT}/card`)).json;
  for (const p of ['subject.botId', 'subject.username', 'subject.didKey', 'subject.publicKeyPem', 'bond.status', 'bond.amountLamports', 'bond.requiredLamports', 'bond.asOf', 'exportMeta.mintedAt', 'exportMeta.ttlSeconds', 'exportMeta.exporterDidKey', 'bundleHash', 'signature']) {
    const v = p.split('.').reduce((o, k) => (o == null ? undefined : o[k]), c);
    must(v !== undefined, 'missing ' + p);
  }
});

// 3. register round trip (persisted throwaway conformance bot)
let me = null;
await check('register: round trip (201 first time, 200 after) + recovery commitment', async () => {
  let key;
  if (fs.existsSync(KEY_FILE)) key = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
  else {
    key = await sdk.generateKeys({ recovery: true });
    key = { publicKeyPem: key.publicKeyPem, privateKeyPem: key.privateKeyPem, recoveryKeyHash: key.recovery.recoveryKeyHash };
    // The recovery private key is deliberately discarded: this is a throwaway test bot.
    fs.writeFileSync(KEY_FILE, JSON.stringify(key), { mode: 0o600 });
  }
  const r1 = await sdk.register(key.publicKeyPem, { username: USERNAME, displayName: 'Moonsox SDK conformance (test bot)', recoveryKeyHash: key.recoveryKeyHash });
  must(/^bot_[0-9a-f]{24}$/.test(r1.botId), 'botId');
  must(r1.recoveryKeySet === true, 'recoveryKeySet');
  const r2 = await sdk.register(key.publicKeyPem, { recoveryKeyHash: 'A'.repeat(43) });
  must(r2.created === false && r2.botId === r1.botId && r2.recoveryKeySet === true, 'repeat must be 200 with the same botId');
  me = { ...key, botId: r1.botId };
  return `${r1.botId} ${r1.created ? 'created' : 'existing'} @${r1.username}`;
});
await check('register: frozen errors', async () => {
  const a = await post('/sdk/v1/register', { publicKey: 'not-a-key' });
  must(a.status === 400 && a.json.error === 'invalid_public_key', a.text);
  const b = await post('/sdk/v1/register', { publicKey: (await sdk.generateKeys()).publicKeyPem, recoveryKeyHash: 'x' });
  must(b.status === 400 && b.json.error === 'invalid_recovery_key_hash', b.text);
  must(a.headers.get('access-control-allow-origin') == null, 'POST must not send CORS');
});

// 4. JWKS: every Signature-Agent location serves the same key
await check('jwks: /sdk/v1 + alias + legacy /v1 forms serve the key', async () => {
  must(me, 'no bot');
  const kid = kidOf(me.publicKeyPem);
  for (const p of [`/sdk/v1/bots/${me.botId}/jwks`, `/sdk/v1/bots/${me.botId}/.well-known/http-message-signatures-directory`, `/v1/bots/${me.botId}/jwks`, `/v1/bots/${me.botId}/.well-known/http-message-signatures-directory`]) {
    const r = await get(p);
    must(r.status === 200, p + ' ' + r.status);
    must((r.json.keys || []).some((k) => k.kid === kid), p + ' missing kid');
    if (p.startsWith('/sdk/')) {
      must(r.headers.get('access-control-allow-origin') === '*', p + ' CORS');
      must(r.json.moonsox.botId === me.botId, p + ' moonsox.botId');
    }
  }
  const nf = await get('/sdk/v1/bots/bot_000000000000000000000000/jwks');
  must(nf.status === 404 && nf.json.error === 'not_found', 'unknown bot -> 404 not_found');
});

// 5. sign + verify round trip (local and server), with body / content-digest
const URL_ = 'https://conformance.example/sdk/v1/check';
await check('sign+verify: local verifyRequest with body (content-digest)', async () => {
  const body = JSON.stringify({ at: Date.now(), msg: 'conformance' });
  const h = await sdk.signRequest({ method: 'POST', url: URL_, body }, { botId: me.botId, privateKeyPem: me.privateKeyPem });
  const v = await sdk.verifyRequest({ method: 'POST', url: URL_, headers: h, body });
  must(v.ok && v.botId === me.botId && v.bodyCovered === true, JSON.stringify(v));
  must(v.card && v.card.botId === me.botId, 'card summary expected (got ' + JSON.stringify(v.card) + ')');
  const bad = await sdk.verifyRequest({ method: 'POST', url: URL_, headers: h, body: body + ' ' });
  must(!bad.ok && bad.reason === 'digest_mismatch', JSON.stringify(bad));
  const nob = await sdk.verifyRequest({ method: 'POST', url: URL_, headers: h });
  must(!nob.ok && nob.reason === 'body_missing', JSON.stringify(nob));
});
await check('sign+verify: server /v1/verify/http-signature accepts SDK signatures + checks content-digest', async () => {
  const body = JSON.stringify({ at: Date.now() });
  const h = await sdk.signRequest({ method: 'POST', url: URL_, body }, { botId: me.botId, privateKeyPem: me.privateKeyPem });
  const ok = await post('/v1/verify/http-signature', { method: 'POST', url: URL_, headers: h, body });
  must(ok.json && ok.json.valid === true && ok.json.botId === me.botId && ok.json.digestVerified === true, ok.text);
  const bad = await post('/v1/verify/http-signature', { method: 'POST', url: URL_, headers: h, body: body + 'x' });
  must(bad.json && bad.json.valid === false && bad.json.error === 'digest_mismatch', bad.text);
  const h0 = await sdk.signRequest({ method: 'GET', url: URL_ }, { botId: me.botId, privateKeyPem: me.privateKeyPem });
  const ok0 = await post('/v1/verify/http-signature', { method: 'GET', url: URL_, headers: h0 });
  must(ok0.json && ok0.json.valid === true && ok0.json.bodyCovered === false, ok0.text);
});
await check('sign+verify: golden signed request against all 4 Signature-Agent forms (local + server)', async () => {
  const forms = [`/sdk/v1/bots/${me.botId}/jwks`, `/v1/bots/${me.botId}/jwks`, `/sdk/v1/bots/${me.botId}/.well-known/http-message-signatures-directory`, `/v1/bots/${me.botId}/.well-known/http-message-signatures-directory`];
  for (const f of forms) {
    const h = legacySign({ method: 'GET', url: URL_, agentUrl: PROD + f, privateKeyPem: me.privateKeyPem });
    const v = await sdk.verifyRequest({ method: 'GET', url: URL_, headers: h });
    must(v.ok, f + ' local ' + JSON.stringify(v));
    const s = await post('/v1/verify/http-signature', { method: 'GET', url: URL_, headers: h });
    must(s.json && s.json.valid === true, f + ' server ' + s.text);
  }
  const evil = legacySign({ method: 'GET', url: URL_, agentUrl: `https://evil.example/v1/bots/${me.botId}/jwks`, privateKeyPem: me.privateKeyPem });
  must((await sdk.verifyRequest({ method: 'GET', url: URL_, headers: evil })).reason === 'unknown_agent', 'foreign agent must be refused');
});

// 6. offline card verify for the conformance bot
await check('card: conformance bot card verifies offline; tamper detected', async () => {
  const c = (await get(`/sdk/v1/bots/${me.botId}/card`)).json;
  const r = await sdk.verifyCard(c);
  must(r.ok && r.summary.botId === me.botId, JSON.stringify(r));
  const t = structuredClone(c); t.bond.status = 'bonded';
  must((await sdk.verifyCard(t)).reason === 'card_bad_hash', 'tamper');
  return `bondStatus=${r.summary.bondStatus}`;
});

await check('routing: unknown /sdk/v1 path -> 404 not_found; wrong method -> 405', async () => {
  const a = await get('/sdk/v1/definitely-not-a-route');
  must(a.status === 404 && a.json.error === 'not_found', a.text);
  const b = await post('/sdk/v1/issuer', {});
  must(b.status === 405, String(b.status));
});

console.log(`@moonsox/trust conformance against ${BASE}`);
for (const line of results) console.log(line);
console.log(failed ? `FAILED ${failed} check(s)` : `OK ${results.length} checks`);
process.exit(failed ? 1 : 0);
