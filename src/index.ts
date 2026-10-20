/**
 * @moonsox/trust 1.x: Moonsox Trust identity for bots and sites.
 *
 * Six functions, frozen for all of 1.x:
 *   bot side:  generateKeys, register, signRequest
 *   site side: verifyRequest, getCard, verifyCard
 *
 * Zero runtime dependencies: WebCrypto (Ed25519, SHA-256) only. Private keys never leave the
 * process; this package never sends or logs a private key. It talks only to
 * https://trust.moonsox.com/sdk/v1/ (a frozen API namespace).
 *
 * MIT licence. See README.md.
 */

// ---------------------------------------------------------------------------------------------
// Public types (additive-only forever)
// ---------------------------------------------------------------------------------------------

export interface KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface GeneratedKeys extends KeyPair {
  /** Present only with generateKeys({ recovery: true }). Move recovery.privateKeyPem offline now. */
  recovery?: KeyPair & { recoveryKeyHash: string };
}

export interface RegisterProfile {
  displayName?: string;
  username?: string;
  /** RFC 7638 thumbprint of your backup (recovery) public key. Accepted on first registration only. */
  recoveryKeyHash?: string;
}

export interface RegisterResult {
  botId: string;
  username: string | null;
  created: boolean;
  recoveryKeySet: boolean;
  /** The server's opaque `extras` object, untouched. Not interpreted by the SDK. */
  raw: Record<string, unknown>;
}

export interface CardSummary {
  botId: string;
  username: string | null;
  didKey: string;
  /** true only when bond.status === "bonded". Any other or unknown status reads as not bonded. */
  bonded: boolean;
  bondStatus: string;
  amountLamports: number;
  requiredLamports: number;
  mintedAt: string;
  bondAsOf: string;
}

export type VerifyResult =
  | { ok: true; botId: string; keyid: string; created: number; expires: number; bodyCovered: boolean; card: CardSummary | null }
  | { ok: false; reason: string; botId?: string };

export type CardResult =
  | { ok: true; summary: CardSummary; card: Record<string, unknown> }
  | { ok: false; reason: string };

export class MoonsoxError extends Error {
  readonly status: number;
  readonly error: string;
  constructor(status: number, error: string, message?: string) {
    super(message ? `${error}: ${message}` : error);
    this.name = 'MoonsoxError';
    this.status = status;
    this.error = error;
  }
}

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

const HOST = 'trust.moonsox.com';
const API = `https://${HOST}/sdk/v1`;
/** Today's card issuer key, pinned. A new issuer key is accepted only if its endorsement chains here. */
const PINNED_ISSUER_DIDS: readonly string[] = ['did:key:z6Mksvo92UP18ArfRs7BJdZNEPXjbPAe2yiw4nN2iJENvNvj'];
const SIG_TTL_SEC = 300;
const CLOCK_SKEW_SEC = 60;
const JWKS_CACHE_MS = 60_000;
const FETCH_TIMEOUT_MS = 10_000;
const BOT_ID_RE = /^bot_[0-9a-f]{24}$/;
const LABEL = 'sig';

// ---------------------------------------------------------------------------------------------
// Encoding helpers (no Buffer: works in browsers and Workers)
// ---------------------------------------------------------------------------------------------

const enc = new TextEncoder();

function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function bytesToB64url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(s: string): Uint8Array {
  const b = s.replace(/-/g, '+').replace(/_/g, '/');
  return b64ToBytes(b + '='.repeat((4 - (b.length % 4)) % 4));
}
function hex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function toBytes(body: string | Uint8Array): Uint8Array {
  return typeof body === 'string' ? enc.encode(body) : body;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58encode(buf: Uint8Array): string {
  let zeros = 0;
  while (zeros < buf.length && buf[zeros] === 0) zeros++;
  const digits = [0];
  for (const byte of buf) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}
// ---------------------------------------------------------------------------------------------
// WebCrypto + key formats
// ---------------------------------------------------------------------------------------------

let subtlePromise: Promise<SubtleCrypto> | null = null;
function subtle(): Promise<SubtleCrypto> {
  if (!subtlePromise) {
    subtlePromise = (async () => {
      const g = globalThis as { crypto?: Crypto };
      if (g.crypto && g.crypto.subtle) return g.crypto.subtle;
      // Node 18 without the global: fall back to node:crypto's webcrypto (specifier kept dynamic for bundlers).
      const spec = 'node:crypto';
      const mod = (await import(/* @vite-ignore */ /* webpackIgnore: true */ spec)) as { webcrypto: Crypto };
      return mod.webcrypto.subtle;
    })();
  }
  return subtlePromise;
}
async function randomBytes(n: number): Promise<Uint8Array> {
  const g = globalThis as { crypto?: Crypto };
  const out = new Uint8Array(n);
  if (g.crypto && typeof g.crypto.getRandomValues === 'function') return g.crypto.getRandomValues(out);
  const spec = 'node:crypto';
  const mod = (await import(/* @vite-ignore */ /* webpackIgnore: true */ spec)) as { webcrypto: Crypto };
  return mod.webcrypto.getRandomValues(out);
}

const ED = { name: 'Ed25519' } as const;
const SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

function pemBody(pem: string, label: string): Uint8Array {
  if (typeof pem !== 'string') throw new TypeError(`${label} PEM string required`);
  const m = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`).exec(pem);
  if (!m) throw new TypeError(`expected a ${label} PEM`);
  return b64ToBytes(m[1].replace(/\s+/g, ''));
}
function toPem(der: Uint8Array, label: string): string {
  const b64 = bytesToB64(der);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}
function rawFromSpkiPem(publicKeyPem: string): Uint8Array {
  const der = pemBody(publicKeyPem, 'PUBLIC KEY');
  if (der.length !== 44 || SPKI_PREFIX.some((b, i) => der[i] !== b)) throw new TypeError('expected an Ed25519 SPKI public key');
  return der.subarray(12);
}
async function importPublicRaw(raw: Uint8Array): Promise<CryptoKey> {
  return (await subtle()).importKey('raw', raw, ED, false, ['verify']);
}
async function importPrivatePem(privateKeyPem: string): Promise<CryptoKey> {
  const der = pemBody(privateKeyPem, 'PRIVATE KEY');
  try {
    return await (await subtle()).importKey('pkcs8', der, ED, false, ['sign']);
  } catch {
    throw new TypeError('expected an Ed25519 PKCS#8 private key');
  }
}
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await (await subtle()).digest('SHA-256', data));
}
async function edVerify(raw: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  if (sig.length !== 64 || raw.length !== 32) return false;
  try {
    return await (await subtle()).verify(ED, await importPublicRaw(raw), sig, msg);
  } catch {
    return false;
  }
}
/** RFC 7638 thumbprint of an Ed25519 public key (members crv, kty, x in lexical order). */
async function thumbprintRaw(raw: Uint8Array): Promise<string> {
  const x = bytesToB64url(raw);
  return bytesToB64url(await sha256(enc.encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`)));
}
function didKeyFromRaw(raw: Uint8Array): string {
  return 'did:key:z' + b58encode(concat(new Uint8Array([0xed, 0x01]), raw));
}
function rawFromDidKey(did: string): Uint8Array | null {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) return null;
  const bytes = b58decodeStrict(did.slice('did:key:z'.length));
  if (!bytes || bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) return null;
  return bytes.subarray(2);
}
function b58decodeStrict(s: string): Uint8Array | null {
  let n = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    n = n * 58n + BigInt(v);
  }
  const out: number[] = [];
  while (n > 0n) { out.push(Number(n & 0xffn)); n >>= 8n; }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...out.reverse()]);
}

// ---------------------------------------------------------------------------------------------
// Network (only https://trust.moonsox.com/sdk/v1)
// ---------------------------------------------------------------------------------------------

type Resp = { status: number; json: unknown; text: string; retryAfter: number | null };

async function call(path: string, init?: { method?: string; body?: unknown }): Promise<Resp> {
  const url = API + path;
  for (let attempt = 0; ; attempt++) {
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS) : null;
    let r: Response;
    try {
      r = await fetch(url, {
        method: init?.method || 'GET',
        headers: init?.body !== undefined ? { 'content-type': 'application/json', accept: 'application/json' } : { accept: 'application/json' },
        body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
        signal: ctrl ? ctrl.signal : undefined,
        redirect: 'follow',
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
    const text = await r.text();
    let json: unknown = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    const ra = r.headers.get('retry-after');
    const retryAfter = ra != null && /^\d+$/.test(ra.trim()) ? Number(ra.trim()) : null;
    if (r.status === 429 && attempt === 0 && retryAfter != null && retryAfter <= 5) {
      await new Promise((res) => setTimeout(res, retryAfter * 1000));
      continue;
    }
    return { status: r.status, json, text, retryAfter };
  }
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

// ---------------------------------------------------------------------------------------------
// 1. generateKeys
// ---------------------------------------------------------------------------------------------

async function makePair(): Promise<{ pair: KeyPair; raw: Uint8Array }> {
  const s = await subtle();
  const kp = (await s.generateKey(ED, true, ['sign', 'verify'])) as CryptoKeyPair;
  const spki = new Uint8Array(await s.exportKey('spki', kp.publicKey));
  const pkcs8 = new Uint8Array(await s.exportKey('pkcs8', kp.privateKey));
  return { pair: { publicKeyPem: toPem(spki, 'PUBLIC KEY'), privateKeyPem: toPem(pkcs8, 'PRIVATE KEY') }, raw: spki.subarray(12) };
}

/**
 * Make a new Ed25519 identity (SPKI PEM public, PKCS#8 PEM private).
 * With { recovery: true } also makes an independent backup keypair and its recoveryKeyHash.
 * The backup key is the account: store recovery.privateKeyPem offline and never load it on the bot.
 */
export async function generateKeys(opts?: { recovery?: boolean }): Promise<GeneratedKeys> {
  if (opts != null && typeof opts !== 'object') throw new TypeError('generateKeys(opts?: { recovery?: boolean })');
  const main = await makePair();
  const out: GeneratedKeys = { ...main.pair };
  if (opts && opts.recovery === true) {
    const rec = await makePair();
    out.recovery = { ...rec.pair, recoveryKeyHash: await thumbprintRaw(rec.raw) };
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// 2. register
// ---------------------------------------------------------------------------------------------

/**
 * Register a public key on Moonsox Trust. Idempotent: the same key returns the same botId
 * (created:false). Throws MoonsoxError { status, error } on failure.
 */
export async function register(publicKeyPem: string, profile?: RegisterProfile): Promise<RegisterResult> {
  if (typeof publicKeyPem !== 'string') throw new TypeError('register(publicKeyPem: string, profile?)');
  rawFromSpkiPem(publicKeyPem);
  if (profile != null && typeof profile !== 'object') throw new TypeError('profile must be an object');
  const body: Record<string, string> = { publicKey: publicKeyPem };
  if (profile?.displayName !== undefined) body.displayName = profile.displayName;
  if (profile?.username !== undefined) body.username = profile.username;
  if (profile?.recoveryKeyHash !== undefined) body.recoveryKeyHash = profile.recoveryKeyHash;
  let r: Resp;
  try {
    r = await call('/register', { method: 'POST', body });
  } catch (e) {
    throw new MoonsoxError(0, 'network', e instanceof Error ? e.message : String(e));
  }
  const j = isObj(r.json) ? r.json : {};
  if ((r.status === 200 || r.status === 201) && typeof j.botId === 'string') {
    return {
      botId: j.botId,
      username: typeof j.username === 'string' ? j.username : null,
      created: r.status === 201,
      recoveryKeySet: j.recoveryKeySet === true,
      raw: isObj(j.extras) ? j.extras : {},
    };
  }
  const code = typeof j.error === 'string' ? j.error : r.status === 429 ? 'rate_limited' : 'http_' + r.status;
  throw new MoonsoxError(r.status, code, typeof j.message === 'string' ? j.message : undefined);
}

// ---------------------------------------------------------------------------------------------
// 3. signRequest (RFC 9421 / Web Bot Auth, + RFC 9530 Content-Digest when there is a body)
// ---------------------------------------------------------------------------------------------

function sfString(s: string): string {
  if (!/^[\x20-\x7e]*$/.test(s)) throw new TypeError('header value must be printable ASCII');
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/**
 * Sign an outgoing HTTP request. Returns the headers to add:
 * Signature-Agent, Signature-Input, Signature (+ Content-Digest when a body is given).
 * Sign exactly the body bytes you send.
 */
export async function signRequest(
  req: { method: string; url: string; body?: string | Uint8Array },
  key: { botId: string; privateKeyPem: string },
): Promise<Record<string, string>> {
  if (!req || typeof req.method !== 'string' || typeof req.url !== 'string') throw new TypeError('signRequest({ method, url, body? }, key)');
  if (!key || typeof key.botId !== 'string' || !BOT_ID_RE.test(key.botId)) throw new TypeError('key.botId must be a bot_ id');
  if (req.body != null && typeof req.body !== 'string' && !(req.body instanceof Uint8Array)) throw new TypeError('body must be a string or Uint8Array');
  const u = new URL(req.url);
  const priv = await importPrivatePem(key.privateKeyPem);
  const s = await subtle();
  // Derive the public key (kid) from the private key via a JWK round trip.
  const pubRaw = await publicRawFromPrivatePem(key.privateKeyPem);
  const kid = await thumbprintRaw(pubRaw);
  const method = req.method.toUpperCase();
  const agent = sfString(`${API}/bots/${key.botId}/jwks`);
  const headers: Record<string, string> = { 'Signature-Agent': agent };
  const components: Array<[string, string]> = [
    ['@method', method],
    ['@authority', u.host.toLowerCase()],
    ['@path', u.pathname || '/'],
    ['signature-agent', agent],
  ];
  if (req.body != null) {
    const digest = `sha-256=:${bytesToB64(await sha256(toBytes(req.body)))}:`;
    headers['Content-Digest'] = digest;
    components.push(['content-digest', digest]);
  }
  const created = Math.floor(Date.now() / 1000);
  const expires = created + SIG_TTL_SEC;
  const nonce = 'n' + bytesToB64url(await randomBytes(18));
  const params = `(${components.map(([n]) => `"${n}"`).join(' ')});created=${created};expires=${expires};keyid="${kid}";alg="ed25519";nonce="${nonce}";tag="web-bot-auth"`;
  const base = components.map(([n, v]) => `"${n}": ${v}`).join('\n') + `\n"@signature-params": ${params}`;
  const sig = new Uint8Array(await s.sign(ED, priv, enc.encode(base)));
  headers['Signature-Input'] = `${LABEL}=${params}`;
  headers['Signature'] = `${LABEL}=:${bytesToB64(sig)}:`;
  return headers;
}

async function publicRawFromPrivatePem(privateKeyPem: string): Promise<Uint8Array> {
  const s = await subtle();
  const der = pemBody(privateKeyPem, 'PRIVATE KEY');
  const k = await s.importKey('pkcs8', der, ED, true, ['sign']);
  const jwk = (await s.exportKey('jwk', k)) as JsonWebKey;
  if (!jwk.x) throw new TypeError('expected an Ed25519 PKCS#8 private key');
  return b64urlToBytes(jwk.x);
}

// ---------------------------------------------------------------------------------------------
// Structured-field parsing (just enough of RFC 8941 for Signature-Input / Signature / Signature-Agent)
// ---------------------------------------------------------------------------------------------

/** Split a dictionary header into [name, rawValue] members (commas inside quotes/parens/colons ignored). */
function dictMembers(h: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let i = 0;
  const n = h.length;
  while (i < n) {
    while (i < n && (h[i] === ' ' || h[i] === '\t' || h[i] === ',')) i++;
    const start = i;
    while (i < n && /[a-z0-9_\-.*]/.test(h[i])) i++;
    const name = h.slice(start, i);
    if (!name) return out;
    if (h[i] !== '=') { // boolean member
      while (i < n && h[i] !== ',') i++;
      out.push([name, '?1']);
      continue;
    }
    i++;
    const vs = i;
    let depth = 0;
    let inStr = false;
    let inBytes = false;
    while (i < n) {
      const c = h[i];
      if (inStr) { if (c === '\\') i++; else if (c === '"') inStr = false; }
      else if (inBytes) { if (c === ':') inBytes = false; }
      else if (c === '"') inStr = true;
      else if (c === ':') inBytes = true;
      else if (c === '(') depth++;
      else if (c === ')') depth--;
      else if (c === ',' && depth === 0) break;
      i++;
    }
    out.push([name, h.slice(vs, i).trim()]);
  }
  return out;
}

function unquote(v: string): string | null {
  if (v.length < 2 || v[0] !== '"' || v[v.length - 1] !== '"') return null;
  return v.slice(1, -1).replace(/\\(["\\])/g, '$1');
}

type ParsedInput = { components: Array<{ name: string; key: string | null }>; params: Record<string, string | number>; raw: string };

function parseInnerList(raw: string): ParsedInput | null {
  const m = /^\(([^)]*)\)(.*)$/s.exec(raw);
  if (!m) return null;
  const components: Array<{ name: string; key: string | null }> = [];
  const itemRe = /"((?:[^"\\]|\\.)*)"((?:;[a-z0-9_\-.*]+(?:=(?:"(?:[^"\\]|\\.)*"|[^\s;"]+))?)*)/g;
  const inner = m[1].trim();
  let consumed = '';
  let im: RegExpExecArray | null;
  while ((im = itemRe.exec(inner))) {
    consumed += im[0];
    const keyM = /;key="([^"]*)"/.exec(im[2] || '');
    if (im[2] && !/^(;key="[^"]*")?$/.test(im[2])) return null; // only ;key is meaningful here
    components.push({ name: im[1].toLowerCase(), key: keyM ? keyM[1] : null });
  }
  if (consumed.replace(/\s/g, '') !== inner.replace(/\s/g, '')) return null;
  const params: Record<string, string | number> = {};
  const pRe = /;\s*([a-z0-9_\-.*]+)(?:=("(?:[^"\\]|\\.)*"|[^\s;]+))?/g;
  let pm: RegExpExecArray | null;
  let pConsumed = '';
  while ((pm = pRe.exec(m[2]))) {
    pConsumed += pm[0];
    const v = pm[2];
    if (v == null) params[pm[1]] = 'true';
    else if (v.startsWith('"')) params[pm[1]] = unquote(v) ?? '';
    else if (/^-?\d+$/.test(v)) params[pm[1]] = Number(v);
    else params[pm[1]] = v;
  }
  if (pConsumed.replace(/\s/g, '') !== m[2].replace(/\s/g, '')) return null;
  return { components, params, raw };
}

function headerGetter(h: Record<string, string> | Headers): (name: string) => string | null {
  if (typeof Headers !== 'undefined' && h instanceof Headers) return (n) => h.get(n);
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (v == null) continue;
    const key = k.toLowerCase();
    const val = Array.isArray(v) ? v.join(', ') : String(v);
    lower[key] = key in lower ? `${lower[key]}, ${val}` : val;
  }
  return (n) => (n in lower ? lower[n] : null);
}

/** Allowlisted Signature-Agent locations (spec §3.3). Returns the botId or null. */
function agentBotId(agentUrl: string): string | null {
  let u: URL;
  try { u = new URL(agentUrl); } catch { return null; }
  if (u.protocol !== 'https:' || u.host !== HOST || u.search || u.hash || u.username || u.password) return null;
  const m = /^\/(?:sdk\/v1|v1)\/bots\/(bot_[0-9a-f]{24})\/(?:jwks|\.well-known\/http-message-signatures-directory)$/.exec(u.pathname);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------------------------
// JWKS + issuer caches
// ---------------------------------------------------------------------------------------------

type Jwk = { kty?: string; crv?: string; x?: string; kid?: string };
const jwksCache = new Map<string, { at: number; keys: Jwk[] | null }>();

async function fetchJwks(botId: string): Promise<{ keys: Jwk[] } | 'not_found' | 'network'> {
  const hit = jwksCache.get(botId);
  if (hit && Date.now() - hit.at < JWKS_CACHE_MS) return hit.keys ? { keys: hit.keys } : 'not_found';
  let r: Resp;
  try { r = await call(`/bots/${botId}/jwks`); } catch { return 'network'; }
  if (r.status === 404) { jwksCache.set(botId, { at: Date.now(), keys: null }); return 'not_found'; }
  if (r.status !== 200 || !isObj(r.json) || !Array.isArray(r.json.keys)) return 'network';
  const meta = r.json.moonsox;
  if (isObj(meta) && typeof meta.botId === 'string' && meta.botId !== botId) return 'not_found';
  const keys = (r.json.keys as unknown[]).filter(isObj) as Jwk[];
  jwksCache.set(botId, { at: Date.now(), keys });
  return { keys };
}

type IssuerKey = { didKey: string; raw: Uint8Array; status: string; since: string | null; until: string | null };
const issuerKeys = new Map<string, IssuerKey>();
for (const did of PINNED_ISSUER_DIDS) {
  const raw = rawFromDidKey(did);
  if (raw) issuerKeys.set(did, { didKey: did, raw, status: 'current', since: null, until: null });
}

/** Fetch /sdk/v1/issuer and accept keys that are pinned or chain back to a pinned key by endorsement. */
async function refreshIssuer(): Promise<void> {
  let r: Resp;
  try { r = await call('/issuer'); } catch { return; }
  if (r.status !== 200 || !isObj(r.json) || !Array.isArray(r.json.keys)) return;
  const pending = (r.json.keys as unknown[]).filter(isObj);
  let progress = true;
  while (progress) {
    progress = false;
    for (const k of pending.splice(0)) {
      const did = typeof k.didKey === 'string' ? k.didKey : '';
      const raw = rawFromDidKey(did);
      let pemOk = true;
      if (raw && typeof k.publicKeyPem === 'string') {
        try { pemOk = hex(rawFromSpkiPem(k.publicKeyPem)) === hex(raw); } catch { pemOk = false; }
      }
      if (!raw || !pemOk) continue;
      const status = typeof k.status === 'string' ? k.status : 'current';
      const since = typeof k.since === 'string' ? k.since : null;
      const until = typeof k.until === 'string' ? k.until : null;
      const known = issuerKeys.get(did);
      if (known) {
        // Pinned/accepted already: only status metadata is taken from the server.
        known.status = status; known.since = since; known.until = until;
        continue;
      }
      const by = typeof k.endorsedBy === 'string' ? issuerKeys.get(k.endorsedBy) : undefined;
      if (by && typeof k.endorsement === 'string' && since) {
        let sig: Uint8Array;
        try { sig = b64ToBytes(k.endorsement); } catch { continue; }
        if (await edVerify(by.raw, sig, enc.encode(`moonsox-sdk-issuer/v1|${did}|${since}`))) {
          issuerKeys.set(did, { didKey: did, raw, status, since, until });
          progress = true;
          continue;
        }
      }
      pending.push(k);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Canonical JSON (RFC 8785 JCS for the JSON values cards contain)
// ---------------------------------------------------------------------------------------------

function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : canonicalJson(x))).join(',') + ']';
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(o[k])).join(',') + '}';
}

// ---------------------------------------------------------------------------------------------
// 6. verifyCard (offline)
// ---------------------------------------------------------------------------------------------

function str(v: unknown): string { return typeof v === 'string' ? v : ''; }
function num(v: unknown): number { return typeof v === 'number' && Number.isFinite(v) ? v : 0; }

/**
 * Verify a card offline: bundleHash, the issuer signature (pinned key, or one that chains to it),
 * and freshness (default: the card's own ttlSeconds). Never throws on a failed check.
 */
export async function verifyCard(card: object, opts?: { maxAgeSec?: number }): Promise<CardResult> {
  if (!card || typeof card !== 'object' || Array.isArray(card)) throw new TypeError('verifyCard(card: object, opts?)');
  if (opts != null && (typeof opts !== 'object' || (opts.maxAgeSec !== undefined && (typeof opts.maxAgeSec !== 'number' || !(opts.maxAgeSec >= 0))))) {
    throw new TypeError('opts.maxAgeSec must be a non-negative number');
  }
  const c = card as Record<string, unknown>;
  const { bundleHash, signature, ...rest } = c;
  if (typeof bundleHash !== 'string' || typeof signature !== 'string') return { ok: false, reason: 'card_bad_hash' };
  const expect = hex(await sha256(enc.encode(canonicalJson(rest))));
  if (expect !== bundleHash) return { ok: false, reason: 'card_bad_hash' };
  const meta = isObj(c.exportMeta) ? c.exportMeta : {};
  const mintedAt = str(meta.mintedAt);
  const mintedMs = Date.parse(mintedAt);
  const issuerDid = str(meta.exporterDidKey);
  const candidates = issuerDid ? [issuerKeys.get(issuerDid)].filter(Boolean) as IssuerKey[] : [...issuerKeys.values()];
  if (!candidates.length) return { ok: false, reason: 'card_unknown_issuer' };
  let sigBytes: Uint8Array;
  try { sigBytes = b64ToBytes(signature); } catch { return { ok: false, reason: 'card_bad_signature' }; }
  let signer: IssuerKey | null = null;
  for (const k of candidates) {
    if (await edVerify(k.raw, sigBytes, enc.encode(bundleHash))) { signer = k; break; }
  }
  if (!signer) return { ok: false, reason: 'card_bad_signature' };
  if (signer.status === 'retired' && signer.until) {
    const until = Date.parse(signer.until);
    if (!Number.isFinite(mintedMs) || (Number.isFinite(until) && mintedMs > until)) return { ok: false, reason: 'card_unknown_issuer' };
  }
  const maxAge = opts?.maxAgeSec ?? (typeof meta.ttlSeconds === 'number' && meta.ttlSeconds > 0 ? meta.ttlSeconds : 86400);
  const now = Date.now();
  if (!Number.isFinite(mintedMs) || now - mintedMs > maxAge * 1000 || mintedMs - now > CLOCK_SKEW_SEC * 1000 * 5) {
    return { ok: false, reason: 'card_stale' };
  }
  const subject = isObj(c.subject) ? c.subject : {};
  const bond = isObj(c.bond) ? c.bond : {};
  const botId = str(subject.botId);
  if (!botId) return { ok: false, reason: 'card_bad_hash' };
  const summary: CardSummary = {
    botId,
    username: typeof subject.username === 'string' ? subject.username : null,
    didKey: str(subject.didKey),
    bonded: bond.status === 'bonded',
    bondStatus: str(bond.status),
    amountLamports: num(bond.amountLamports),
    requiredLamports: num(bond.requiredLamports),
    mintedAt,
    bondAsOf: str(bond.asOf),
  };
  return { ok: true, summary, card: c };
}

// ---------------------------------------------------------------------------------------------
// 5. getCard
// ---------------------------------------------------------------------------------------------

/** Fetch a bot's registry-signed card by botId (bot_...) or username, verified before it is returned. */
export async function getCard(botIdOrUsername: string): Promise<CardResult> {
  if (typeof botIdOrUsername !== 'string' || !botIdOrUsername) throw new TypeError('getCard(botIdOrUsername: string)');
  const isId = botIdOrUsername.startsWith('bot_');
  if (isId && !BOT_ID_RE.test(botIdOrUsername)) return { ok: false, reason: 'card_unavailable' };
  const path = isId ? `/bots/${botIdOrUsername}/card` : `/names/${encodeURIComponent(botIdOrUsername)}/card`;
  let r: Resp;
  try { r = await call(path); } catch { return { ok: false, reason: 'network' }; }
  if (r.status !== 200 || !isObj(r.json)) return { ok: false, reason: 'card_unavailable' };
  const card = r.json;
  const did = isObj(card.exportMeta) ? str(card.exportMeta.exporterDidKey) : '';
  if (did && !issuerKeys.has(did)) await refreshIssuer();
  const res = await verifyCard(card);
  if (res.ok && isId && res.summary.botId !== botIdOrUsername) return { ok: false, reason: 'card_bad_signature' };
  return res;
}

// ---------------------------------------------------------------------------------------------
// 4. verifyRequest
// ---------------------------------------------------------------------------------------------

/**
 * Verify a Web Bot Auth (RFC 9421) signed request locally. ok:true means "this bot's key signed
 * this request" only. Standing is in `card` (null = unknown, not bad). Never throws on a failed check.
 */
export async function verifyRequest(req: {
  method: string;
  url: string;
  headers: Record<string, string> | Headers;
  body?: string | Uint8Array;
}): Promise<VerifyResult> {
  if (!req || typeof req.method !== 'string' || typeof req.url !== 'string' || !req.headers || typeof req.headers !== 'object') {
    throw new TypeError('verifyRequest({ method, url, headers, body? })');
  }
  if (req.body != null && typeof req.body !== 'string' && !(req.body instanceof Uint8Array)) throw new TypeError('body must be a string or Uint8Array');
  let u: URL;
  try { u = new URL(req.url); } catch { throw new TypeError('req.url must be an absolute URL'); }
  const get = headerGetter(req.headers);
  const sigInputH = get('signature-input');
  const sigH = get('signature');
  const agentH = get('signature-agent');
  if (!sigInputH || !sigH || !agentH) return { ok: false, reason: 'missing_headers' };

  // Pick the web-bot-auth signature.
  const inputs = dictMembers(sigInputH);
  if (!inputs.length) return { ok: false, reason: 'bad_signature_input' };
  let label: string | null = null;
  let parsed: ParsedInput | null = null;
  let sawParsed = false;
  for (const [name, raw] of inputs) {
    const p = parseInnerList(raw);
    if (!p) continue;
    sawParsed = true;
    if (p.params.tag === 'web-bot-auth') { label = name; parsed = p; break; }
  }
  if (!sawParsed) return { ok: false, reason: 'bad_signature_input' };
  if (!parsed || !label) return { ok: false, reason: 'bad_tag' };
  const { created, expires, keyid, alg } = parsed.params;
  if (typeof created !== 'number' || typeof expires !== 'number' || typeof keyid !== 'string' || !keyid) {
    return { ok: false, reason: 'bad_signature_input' };
  }
  if (alg !== undefined && alg !== 'ed25519') return { ok: false, reason: 'bad_signature_input' };
  const names = parsed.components.map((c) => c.name);
  if (!names.includes('@authority') || !names.includes('signature-agent')) return { ok: false, reason: 'bad_signature_input' };
  const now = Math.floor(Date.now() / 1000);
  if (now > expires) return { ok: false, reason: 'expired' };
  if (created > now + CLOCK_SKEW_SEC) return { ok: false, reason: 'not_yet_valid' };

  // Signature-Agent (allowlisted locations only).
  const agentComp = parsed.components.find((c) => c.name === 'signature-agent');
  let agentUrl: string | null = null;
  if (agentComp && agentComp.key) {
    const member = dictMembers(agentH).find(([n]) => n === agentComp.key);
    agentUrl = member ? unquote(member[1]) : null;
  } else {
    agentUrl = unquote(agentH.trim());
    if (agentUrl == null) {
      const member = dictMembers(agentH).find(([n]) => n === label) || dictMembers(agentH)[0];
      agentUrl = member ? unquote(member[1]) : null;
    }
  }
  const botId = agentUrl ? agentBotId(agentUrl) : null;
  if (!botId) return { ok: false, reason: 'unknown_agent' };

  // Signature bytes.
  const sigMember = dictMembers(sigH).find(([n]) => n === label);
  const sigM = sigMember ? /^:([A-Za-z0-9+/=]*):$/.exec(sigMember[1]) : null;
  if (!sigM) return { ok: false, reason: 'missing_headers', botId };
  let sigBytes: Uint8Array;
  try { sigBytes = b64ToBytes(sigM[1]); } catch { return { ok: false, reason: 'bad_signature', botId }; }

  // Signature base.
  const lines: string[] = [];
  for (const c of parsed.components) {
    let v: string | null;
    switch (c.name) {
      case '@method': v = req.method.toUpperCase(); break;
      case '@authority': v = u.host.toLowerCase(); break;
      case '@path': v = u.pathname || '/'; break;
      case '@query': v = u.search || '?'; break;
      case '@scheme': v = u.protocol.replace(':', ''); break;
      case '@target-uri': v = u.href; break;
      case '@request-target': v = (u.pathname || '/') + u.search; break;
      default:
        if (c.name.startsWith('@')) return { ok: false, reason: 'bad_signature_input', botId };
        v = get(c.name);
        if (v != null && c.key) {
          const member = dictMembers(v).find(([n]) => n === c.key);
          v = member ? member[1] : null;
        }
        if (v == null) return { ok: false, reason: c.name === 'content-digest' ? 'digest_mismatch' : 'missing_headers', botId };
        v = v.trim();
    }
    lines.push(`"${c.name}"${c.key ? `;key="${c.key}"` : ''}: ${v}`);
  }
  lines.push(`"@signature-params": ${parsed.raw}`);
  const base = enc.encode(lines.join('\n'));

  // Key.
  const jwks = await fetchJwks(botId);
  if (jwks === 'network') return { ok: false, reason: 'network', botId };
  if (jwks === 'not_found') return { ok: false, reason: 'key_not_found', botId };
  const jwk = jwks.keys.find((k) => k.kid === keyid);
  if (!jwk) return { ok: false, reason: 'key_not_found', botId };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return { ok: false, reason: 'key_not_found', botId };
  let raw: Uint8Array;
  try { raw = b64urlToBytes(jwk.x); } catch { return { ok: false, reason: 'key_not_found', botId }; }
  if (raw.length !== 32 || (await thumbprintRaw(raw)) !== keyid) return { ok: false, reason: 'keyid_mismatch', botId };
  if (!(await edVerify(raw, sigBytes, base))) return { ok: false, reason: 'bad_signature', botId };

  // Body (RFC 9530).
  const bodyCovered = names.includes('content-digest');
  if (bodyCovered) {
    if (req.body == null) return { ok: false, reason: 'body_missing', botId };
    const digestH = get('content-digest') || '';
    const members = dictMembers(digestH);
    const want = members.find(([n]) => n === 'sha-256');
    if (!want) return { ok: false, reason: 'digest_mismatch', botId };
    const got = `:${bytesToB64(await sha256(toBytes(req.body)))}:`;
    if (want[1] !== got) return { ok: false, reason: 'digest_mismatch', botId };
  }

  // Standing (card). A card failure never fails the request: card:null = standing unknown.
  let card: CardSummary | null = null;
  try {
    const cr = await getCard(botId);
    if (cr.ok) {
      const cardKid = await (async () => {
        try {
          const subj = (cr.card.subject || {}) as Record<string, unknown>;
          return await thumbprintRaw(rawFromSpkiPem(String(subj.publicKeyPem || '')));
        } catch { return null; }
      })();
      // The signed card is the anchor for the (unsigned) JWKS: its key must be the one that signed.
      const subj = (cr.card.subject || {}) as Record<string, unknown>;
      const extraKids = Array.isArray(subj.keys) ? (subj.keys as unknown[]).filter(isObj).map((k) => k.kid) : [];
      if (cardKid && cardKid !== keyid && !extraKids.includes(keyid)) return { ok: false, reason: 'keyid_mismatch', botId };
      card = cr.summary;
    }
  } catch {
    card = null;
  }
  return { ok: true, botId, keyid, created, expires, bodyCovered, card };
}
