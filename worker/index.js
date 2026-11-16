/**
 * Vitrine — API (Cloudflare Worker, ES Modules)
 *
 * Bindings (wrangler.toml):
 *   DB      → D1 (obrigatório)
 *   ASSETS  → arquivos de /public (Workers Static Assets ou Pages)
 *   IMAGES  → R2 (opcional; sem ele as imagens enviadas são guardadas comprimidas no D1)
 *
 * Segredos (opcionais — wrangler secret put ... / painel do Pages):
 *   MASTER_PASSWORD  → fixa a senha do Master. Sem ele vale a senha salva no painel Master
 *                      (padrão inicial: 1989 — troque em Master → Configurações).
 *   SESSION_SECRET   → assina os logins. Sem ele, um segredo aleatório é gerado e guardado no D1.
 *
 * Variáveis (wrangler.toml [vars]):
 *   TRIAL_DAYS, PLAN_PRICE, SUPPORT_WHATSAPP, ALLOWED_ORIGIN, PUBLIC_BASE_URL
 *
 * Rotas públicas
 *   GET    /api/health
 *   GET    /api/config
 *   GET    /api/store/:tenantId
 *   GET    /api/images/:key+
 *   GET    /api/auth/check-slug?id=        endereço disponível?
 *   POST   /api/auth/register              cadastro com 7 dias grátis
 *   POST   /api/auth/login                 { store_id, password }
 *
 * Rotas do lojista (Authorization: Bearer <token>)
 *   GET    /api/me
 *   POST   /api/me/ping                    presença (online no Master)
 *   PUT    /api/me/profile
 *   PUT    /api/me/settings
 *   PUT    /api/me/password
 *   POST   /api/me/upload                  corpo binário (image/jpeg|png|webp)
 *   POST   /api/me/products
 *   PUT    /api/me/products/:id
 *   PATCH  /api/me/products/:id/visibility { is_visible }
 *   DELETE /api/me/products/:id
 *
 * Rotas Master (X-Master-Password)
 *   GET    /api/admin/tenants              lojas + estatísticas + quem está online
 *   POST   /api/admin/tenants
 *   PATCH  /api/admin/tenants/:id          { action: activate|extend_trial|expire|reset_password|update, ... }
 *   DELETE /api/admin/tenants/:id
 *   GET    /api/admin/config
 *   PUT    /api/admin/config               vídeo da página inicial, WhatsApp de suporte, senha Master
 */

const DAY_MS = 86_400_000;
const ONLINE_WINDOW_MS = 3 * 60_000;      // lojista "online" se deu sinal nos últimos 3 min
const MASTER_DEFAULT_PASSWORD = '1989';   // vale até ser trocada no painel Master
const PBKDF2_ITERATIONS = 100_000; // limite máximo suportado pelo Workers
const TOKEN_TTL_MS = 30 * DAY_MS;
const MAX_JSON_BYTES = 1_000_000;
const MAX_UPLOAD_BYTES = 3_000_000;
const MAX_INLINE_IMAGE_CHARS = 450_000; // imagem em data URL quando não há R2
const MAX_PRODUCTS_PER_TENANT = 500;

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$/;
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
const DATA_IMAGE_RE = /^data:image\/(?:png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/;
const PLATFORMS = ['mercadolivre', 'shopee', 'proprio'];
const RESERVED_SLUGS = new Set([
  'admin', 'api', 'app', 'assets', 'dashboard', 'images', 'img', 'login', 'master',
  'painel', 'public', 'static', 'suporte', 'vitrine', 'www', 'config', 'index',
]);
const UPLOAD_TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ------------------------------------------------------------------ */
/* Infra HTTP                                                          */
/* ------------------------------------------------------------------ */

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Master-Password',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...headers,
    },
  });
}

async function readJson(request) {
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > MAX_JSON_BYTES) throw new HttpError(413, 'Dados grandes demais.');
  const text = await request.text();
  if (text.length > MAX_JSON_BYTES) throw new HttpError(413, 'Dados grandes demais.');
  if (!text) return {};
  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not object');
    return data;
  } catch {
    throw new HttpError(400, 'JSON inválido.');
  }
}

/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

const nowIso = () => new Date().toISOString();
const addDays = (fromMs, days) => new Date(fromMs + days * DAY_MS).toISOString();
const trialDays = (env) => clampInt(env.TRIAL_DAYS, 1, 365, 7);

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function daysLeft(iso) {
  if (!iso) return 0;
  const diff = Date.parse(iso) - Date.now();
  return diff > 0 ? Math.ceil(diff / DAY_MS) : 0;
}

function b64u(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i += 0x8000) bin += String.fromCharCode(...arr.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64u(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

function slugify(text) {
  return String(text || '')
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/g, '');
}

/* ------------------------------------------------------------------ */
/* Validação de entrada                                               */
/* ------------------------------------------------------------------ */

function text(value, max, field, { required = false } = {}) {
  const v = String(value ?? '').replace(/\u0000/g, '').trim();
  if (required && !v) throw new HttpError(400, `Preencha o campo "${field}".`);
  if (v.length > max) throw new HttpError(400, `"${field}" deve ter no máximo ${max} caracteres.`);
  return v;
}

function httpUrl(value, field, { required = false, allowData = false } = {}) {
  const v = String(value ?? '').trim();
  if (!v) {
    if (required) throw new HttpError(400, `Informe o campo "${field}".`);
    return null;
  }
  if (allowData && v.startsWith('data:')) {
    if (!DATA_IMAGE_RE.test(v)) throw new HttpError(400, `"${field}": imagem inválida.`);
    if (v.length > MAX_INLINE_IMAGE_CHARS) throw new HttpError(413, `"${field}": imagem grande demais.`);
    return v;
  }
  if (v.length > 2048) throw new HttpError(400, `"${field}": link longo demais.`);
  let url;
  try {
    url = new URL(v);
  } catch {
    throw new HttpError(400, `"${field}": link inválido. Use um endereço começando com https://`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new HttpError(400, `"${field}": use um link http(s).`);
  }
  return url.toString();
}

function whatsapp(value, { required = false } = {}) {
  let digits = String(value ?? '').replace(/\D/g, '');
  if (!digits) {
    if (required) throw new HttpError(400, 'Informe o WhatsApp com DDD.');
    return '';
  }
  if (digits.length === 10 || digits.length === 11) digits = '55' + digits; // número brasileiro sem DDI
  if (digits.length < 12 || digits.length > 15) {
    throw new HttpError(400, 'WhatsApp inválido. Use DDD + número, ex.: (67) 99999-9999.');
  }
  return digits;
}

function color(value, fallback = '#16a6e0') {
  const v = String(value ?? '').trim();
  if (!v) return fallback;
  if (!COLOR_RE.test(v)) throw new HttpError(400, 'Cor inválida. Use o formato #RRGGBB.');
  return v.toLowerCase();
}

function price(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = typeof value === 'number'
    ? value
    : Number(String(value).replace(/[^\d,.-]/g, '').replace(/\.(?=\d{3}(?:\D|$))/g, '').replace(',', '.'));
  if (!Number.isFinite(n) || n < 0 || n > 99_999_999) throw new HttpError(400, 'Preço inválido.');
  return Math.round(n * 100) / 100;
}

function bool01(value) {
  return value === true || value === 1 || value === '1' || value === 'true' || value === 'on' ? 1 : 0;
}

function password(value, field = 'Senha') {
  const v = String(value ?? '');
  if (v.length < 6) throw new HttpError(400, `${field}: mínimo de 6 caracteres.`);
  if (v.length > 128) throw new HttpError(400, `${field}: máximo de 128 caracteres.`);
  return v;
}

function storeSlug(value) {
  const v = String(value ?? '').trim().toLowerCase();
  if (!SLUG_RE.test(v)) {
    throw new HttpError(400, 'Endereço da loja inválido: use 3 a 40 letras minúsculas, números e hífens (ex.: loja-do-joao).');
  }
  if (RESERVED_SLUGS.has(v)) throw new HttpError(400, 'Este endereço é reservado. Escolha outro.');
  return v;
}

function productInput(body) {
  const platform = String(body.platform || 'proprio');
  if (!PLATFORMS.includes(platform)) throw new HttpError(400, 'Plataforma inválida.');
  const isPhysical = bool01(body.is_physical);
  const product = {
    title: text(body.title, 120, 'Título', { required: true }),
    description: text(body.description, 1500, 'Descrição'),
    price: price(body.price),
    image_url: httpUrl(body.image_url, 'Imagem', { allowData: true }),
    affiliate_link: httpUrl(body.affiliate_link, platform === 'proprio' ? 'Link de compra' : 'Link de afiliado', { required: platform !== 'proprio' }),
    platform,
    is_physical: isPhysical,
    delivery_cities: isPhysical ? text(body.delivery_cities, 500, 'Cidades atendidas') : '',
    sort_order: clampInt(body.sort_order, -100000, 100000, 0),
  };
  if (platform === 'proprio' && isPhysical && !product.delivery_cities) {
    throw new HttpError(400, 'Informe as cidades onde você entrega este produto.');
  }
  return product;
}

/* ------------------------------------------------------------------ */
/* Senhas e sessão                                                     */
/* ------------------------------------------------------------------ */

async function pbkdf2(pw, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 256);
  return new Uint8Array(bits);
}

async function hashPassword(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(pw, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64u(salt)}$${b64u(hash)}`;
}

async function verifyPassword(pw, stored) {
  const [scheme, iter, salt, hash] = String(stored || '').split('$');
  if (scheme !== 'pbkdf2' || !iter || !salt || !hash) return false;
  const iterations = Number(iter);
  if (!Number.isInteger(iterations) || iterations < 1000 || iterations > PBKDF2_ITERATIONS) return false;
  const computed = await pbkdf2(pw, unb64u(salt), iterations);
  return timingSafeEqual(computed, unb64u(hash));
}

// Hash fixo usado quando a loja não existe, para o tempo de resposta não revelar quais lojas existem.
const DUMMY_HASH = 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/* ------------------------------------------------------------------ */
/* Banco: atualização automática e configurações do sistema           */
/* ------------------------------------------------------------------ */

// Garante tabelas/colunas novas em bancos criados por versões anteriores (roda 1x por instância).
let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = (async () => {
      await env.DB.prepare(
        'CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT)',
      ).run();
      const columns = async (table) => {
        const { results } = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
        return new Set((results || []).map((r) => r.name));
      };
      const [tc, pc, sc] = await Promise.all([columns('tenants'), columns('products'), columns('tenant_settings')]);
      const alters = [];
      if (!tc.has('last_seen_at')) alters.push('ALTER TABLE tenants ADD COLUMN last_seen_at TEXT');
      if (!tc.has('last_login_at')) alters.push('ALTER TABLE tenants ADD COLUMN last_login_at TEXT');
      if (!tc.has('views')) alters.push('ALTER TABLE tenants ADD COLUMN views INTEGER NOT NULL DEFAULT 0');
      if (!pc.has('is_visible')) alters.push('ALTER TABLE products ADD COLUMN is_visible INTEGER NOT NULL DEFAULT 1');
      if (!sc.has('show_banner')) alters.push('ALTER TABLE tenant_settings ADD COLUMN show_banner INTEGER NOT NULL DEFAULT 1');
      if (!sc.has('share_message')) alters.push("ALTER TABLE tenant_settings ADD COLUMN share_message TEXT NOT NULL DEFAULT ''");
      for (const sql of alters) {
        try {
          await env.DB.prepare(sql).run();
        } catch (err) {
          if (!/duplicate column/i.test(String(err && err.message))) throw err;
        }
      }
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

async function getConfig(env) {
  const { results } = await env.DB.prepare('SELECT key, value FROM app_config').all();
  return Object.fromEntries((results || []).map((r) => [r.key, r.value]));
}

async function setConfig(env, key, value) {
  await env.DB.prepare(
    `INSERT INTO app_config (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
  ).bind(key, String(value), nowIso()).run();
}

// Converte links do YouTube/Vimeo em endereço de incorporação seguro.
function videoEmbed(raw) {
  const v = String(raw || '').trim();
  if (!v) return null;
  let url;
  try { url = new URL(v); } catch { return null; }
  if (url.protocol !== 'https:') return null;
  const host = url.hostname.replace(/^www\.|^m\./, '');
  let id = null;
  if (host === 'youtu.be') id = url.pathname.slice(1).split('/')[0];
  else if (host === 'youtube.com' || host === 'youtube-nocookie.com') {
    id = url.searchParams.get('v') || (url.pathname.match(/^\/(?:embed|shorts|live)\/([^/?#]+)/) || [])[1];
  }
  if (id && /^[\w-]{6,20}$/.test(id)) return { type: 'iframe', src: `https://www.youtube-nocookie.com/embed/${id}?rel=0&modestbranding=1` };
  if (host === 'vimeo.com' || host === 'player.vimeo.com') {
    const vid = (url.pathname.match(/(\d{6,12})/) || [])[1];
    if (vid) return { type: 'iframe', src: `https://player.vimeo.com/video/${vid}` };
  }
  if (/\.(mp4|webm)$/i.test(url.pathname)) return { type: 'video', src: url.toString() };
  return null;
}

let cachedSecret = null;
async function sessionSecret(env) {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  if (cachedSecret) return cachedSecret;
  // Sem SESSION_SECRET: gera um segredo aleatório uma única vez e guarda no D1.
  await env.DB.prepare('INSERT OR IGNORE INTO app_config (key, value, updated_at) VALUES (?, ?, ?)')
    .bind('session_secret', b64u(crypto.getRandomValues(new Uint8Array(32))), nowIso()).run();
  cachedSecret = await env.DB.prepare("SELECT value FROM app_config WHERE key = 'session_secret'").first('value');
  if (!cachedSecret) throw new HttpError(500, 'Não foi possível iniciar as sessões.');
  return cachedSecret;
}

async function hmacKey(env) {
  return crypto.subtle.importKey(
    'raw', enc.encode('vitrine-session:' + (await sessionSecret(env))),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
  );
}

// "pv" amarra o token ao hash atual da senha: trocar a senha encerra as sessões antigas.
const passwordVersion = (hash) => String(hash).slice(-16);

async function signToken(env, tenant) {
  const body = b64u(enc.encode(JSON.stringify({
    tid: tenant.id,
    pv: passwordVersion(tenant.password_hash),
    exp: Date.now() + TOKEN_TTL_MS,
  })));
  const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(body)));
  return `${body}.${sig}`;
}

async function verifyToken(env, token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env), unb64u(sig), enc.encode(body));
    if (!ok) return null;
    const payload = JSON.parse(dec.decode(unb64u(body)));
    if (!payload.exp || payload.exp < Date.now() || !payload.tid) return null;
    return payload;
  } catch {
    return null;
  }
}

// Ordem: secret MASTER_PASSWORD → senha trocada no painel Master (hash no D1) → padrão 1989.
async function requireMaster(request, env) {
  const given = request.headers.get('X-Master-Password') || '';
  if (!given) throw new HttpError(401, 'Senha Master incorreta.');
  let ok;
  if (env.MASTER_PASSWORD) {
    ok = timingSafeEqual(await sha256(given), await sha256(env.MASTER_PASSWORD));
  } else {
    const stored = await env.DB.prepare("SELECT value FROM app_config WHERE key = 'master_hash'").first('value');
    ok = stored
      ? await verifyPassword(given, stored)
      : timingSafeEqual(await sha256(given), await sha256(MASTER_DEFAULT_PASSWORD));
  }
  if (!ok) throw new HttpError(401, 'Senha Master incorreta.');
}

async function requireTenant(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const payload = await verifyToken(env, token);
  if (!payload) throw new HttpError(401, 'Sessão expirada. Entre novamente.');
  const tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(payload.tid).first();
  if (!tenant || passwordVersion(tenant.password_hash) !== payload.pv) {
    throw new HttpError(401, 'Sessão expirada. Entre novamente.');
  }
  return refreshStatus(env, tenant);
}

function assertCanEdit(tenant) {
  if (tenant.status === 'expired') {
    throw new HttpError(402, 'Seu período de teste terminou. Assine o plano para voltar a editar sua vitrine.', { code: 'expired' });
  }
}

/* ------------------------------------------------------------------ */
/* Regras de assinatura                                               */
/* ------------------------------------------------------------------ */

function isLapsed(tenant, now = Date.now()) {
  if (tenant.status === 'trial') return !tenant.trial_ends_at || Date.parse(tenant.trial_ends_at) <= now;
  if (tenant.status === 'active') return !!tenant.paid_until && Date.parse(tenant.paid_until) <= now;
  return false;
}

async function refreshStatus(env, tenant) {
  if (tenant && isLapsed(tenant)) {
    const ts = nowIso();
    await env.DB.prepare(
      "UPDATE tenants SET status = 'expired', updated_at = ? WHERE id = ? AND status IN ('trial', 'active')",
    ).bind(ts, tenant.id).run();
    tenant.status = 'expired';
    tenant.updated_at = ts;
  }
  return tenant;
}

async function expireLapsedTenants(env) {
  const ts = nowIso();
  await env.DB.prepare(
    `UPDATE tenants SET status = 'expired', updated_at = ?
     WHERE (status = 'trial' AND trial_ends_at <= ?)
        OR (status = 'active' AND paid_until IS NOT NULL AND paid_until <= ?)`,
  ).bind(ts, ts, ts).run();
}

function tenantPublic(t) {
  return {
    id: t.id,
    store_name: t.store_name,
    owner_name: t.owner_name,
    whatsapp: t.whatsapp,
    avatar_url: t.avatar_url,
    theme_color: t.theme_color,
    status: t.status,
    trial_ends_at: t.trial_ends_at,
    trial_expired: Date.parse(t.trial_ends_at) <= Date.now(),
    trial_days_left: t.status === 'trial' ? daysLeft(t.trial_ends_at) : 0,
    is_expired: t.status === 'expired',
  };
}

function tenantPrivate(t) {
  return {
    ...tenantPublic(t),
    paid_until: t.paid_until,
    paid_days_left: t.status === 'active' ? (t.paid_until ? daysLeft(t.paid_until) : null) : 0,
    created_at: t.created_at,
    updated_at: t.updated_at,
    last_seen_at: t.last_seen_at || null,
    last_login_at: t.last_login_at || null,
    views: Number(t.views || 0),
    online: !!t.last_seen_at && Date.now() - Date.parse(t.last_seen_at) < ONLINE_WINDOW_MS,
  };
}

const DEFAULT_SETTINGS = { show_prices: 1, show_stock_warning: 1, view_mode: 'grid', show_banner: 1, share_message: '' };

async function loadSettings(env, tenantId) {
  const row = await env.DB.prepare(
    'SELECT show_prices, show_stock_warning, view_mode, show_banner, share_message FROM tenant_settings WHERE tenant_id = ?',
  ).bind(tenantId).first();
  return row ? { ...DEFAULT_SETTINGS, ...row } : { ...DEFAULT_SETTINGS };
}

async function loadProducts(env, tenantId, { onlyVisible = false } = {}) {
  const { results } = await env.DB.prepare(
    `SELECT id, title, description, price, image_url, affiliate_link, platform,
            is_physical, delivery_cities, sort_order, is_visible, created_at, updated_at
       FROM products WHERE tenant_id = ? ${onlyVisible ? 'AND is_visible = 1' : ''}
      ORDER BY sort_order ASC, id DESC`,
  ).bind(tenantId).all();
  return results || [];
}

async function touchPresence(env, tenantId, { login = false } = {}) {
  const ts = nowIso();
  await env.DB.prepare(
    login
      ? 'UPDATE tenants SET last_seen_at = ?, last_login_at = ? WHERE id = ?'
      : 'UPDATE tenants SET last_seen_at = ? WHERE id = ?',
  ).bind(...(login ? [ts, ts, tenantId] : [ts, tenantId])).run();
  return ts;
}

function publicBase(request, env) {
  return (env.PUBLIC_BASE_URL || new URL(request.url).origin).replace(/\/+$/, '');
}

/* ------------------------------------------------------------------ */
/* Imagens (R2 opcional)                                              */
/* ------------------------------------------------------------------ */

function ownedImageKey(url, tenantId) {
  if (!url || url.startsWith('data:')) return null;
  const m = String(url).match(/\/api\/images\/([^?#]+)/);
  if (!m) return null;
  const key = decodeURIComponent(m[1]);
  return key.startsWith(tenantId + '/') ? key : null;
}

async function deleteImage(env, url, tenantId) {
  const key = ownedImageKey(url, tenantId);
  if (key && env.IMAGES) {
    try { await env.IMAGES.delete(key); } catch { /* imagem já removida */ }
  }
}

async function deleteAllTenantImages(env, tenantId) {
  if (!env.IMAGES) return;
  let cursor;
  do {
    const list = await env.IMAGES.list({ prefix: tenantId + '/', cursor });
    const keys = list.objects.map((o) => o.key);
    if (keys.length) await env.IMAGES.delete(keys);
    cursor = list.truncated ? list.cursor : undefined;
  } while (cursor);
}

/* ------------------------------------------------------------------ */
/* Handlers públicos                                                   */
/* ------------------------------------------------------------------ */

async function handleConfig(request, env) {
  const cfg = await getConfig(env);
  return json({
    app_name: 'Vitrine App',
    trial_days: trialDays(env),
    plan_price: env.PLAN_PRICE || '19,90',
    support_whatsapp: String(cfg.support_whatsapp || env.SUPPORT_WHATSAPP || '').replace(/\D/g, ''),
    video: videoEmbed(cfg.landing_video_url),
    uploads: !!env.IMAGES,
    public_base_url: publicBase(request, env),
  });
}

async function handleStore(env, rawId) {
  const id = String(rawId || '').toLowerCase();
  if (!SLUG_RE.test(id)) throw new HttpError(404, 'Vitrine não encontrada.');
  let tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(id).first();
  if (!tenant) throw new HttpError(404, 'Vitrine não encontrada.');
  tenant = await refreshStatus(env, tenant);

  const [settings, products] = await Promise.all([
    loadSettings(env, id),
    tenant.status === 'expired' ? Promise.resolve([]) : loadProducts(env, id, { onlyVisible: true }),
  ]);
  if (tenant.status !== 'expired') {
    try {
      await env.DB.prepare('UPDATE tenants SET views = views + 1 WHERE id = ?').bind(id).run();
    } catch { /* contador não é crítico */ }
  }
  delete settings.share_message;

  // Quando o lojista oculta preços, o preço nem sai do servidor.
  const visibleProducts = settings.show_prices
    ? products
    : products.map((p) => ({ ...p, price: null }));

  return json({ store: tenantPublic(tenant), settings, products: visibleProducts });
}

async function handleImage(env, key) {
  if (!env.IMAGES) throw new HttpError(404, 'Imagem não encontrada.');
  const object = await env.IMAGES.get(key);
  if (!object) throw new HttpError(404, 'Imagem não encontrada.');
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('ETag', object.httpEtag);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(object.body, { headers });
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const id = String(body.store_id || '').trim().toLowerCase();
  const pw = String(body.password || '');
  const tenant = SLUG_RE.test(id)
    ? await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(id).first()
    : null;
  const ok = await verifyPassword(pw, tenant ? tenant.password_hash : DUMMY_HASH);
  if (!tenant || !ok) throw new HttpError(401, 'Loja ou senha incorretas.');
  await refreshStatus(env, tenant);
  tenant.last_seen_at = tenant.last_login_at = await touchPresence(env, tenant.id, { login: true });
  return json({ token: await signToken(env, tenant), tenant: tenantPrivate(tenant) });
}

async function handleCheckSlug(env, url) {
  const raw = String(url.searchParams.get('id') || '').trim().toLowerCase();
  const id = slugify(raw);
  if (!SLUG_RE.test(id)) return json({ id, available: false, reason: 'Use de 3 a 40 letras, números ou hífens.' });
  if (RESERVED_SLUGS.has(id)) return json({ id, available: false, reason: 'Endereço reservado.' });
  const exists = await env.DB.prepare('SELECT 1 FROM tenants WHERE id = ?').bind(id).first();
  if (!exists) return json({ id, available: true });
  let suggestion = null;
  for (let i = 2; i < 30 && !suggestion; i++) {
    const candidate = `${id.slice(0, 36)}-${i}`;
    if (!(await env.DB.prepare('SELECT 1 FROM tenants WHERE id = ?').bind(candidate).first())) suggestion = candidate;
  }
  return json({ id, available: false, reason: 'Este endereço já está em uso.', suggestion });
}

// Cadastro aberto: cria a loja com 7 dias grátis e já entra no painel.
async function handleRegister(request, env) {
  const body = await readJson(request);
  if (String(body.website || '').trim()) throw new HttpError(400, 'Não foi possível concluir o cadastro.'); // campo-isca anti-robô
  const tenant = await createTenant(request, env, body);
  tenant.last_seen_at = tenant.last_login_at = await touchPresence(env, tenant.id, { login: true });
  const full = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(tenant.id).first();
  return json({
    token: await signToken(env, full),
    tenant: tenantPrivate(full),
    store_url: `${publicBase(request, env)}/s/${tenant.id}`,
  }, 201);
}

/* ------------------------------------------------------------------ */
/* Handlers do lojista                                                 */
/* ------------------------------------------------------------------ */

async function handlePing(env, tenant) {
  await touchPresence(env, tenant.id);
  return json({ ok: true, status: tenant.status });
}

async function handleVisibility(request, env, tenant, rawId) {
  assertCanEdit(tenant);
  const current = await getOwnedProduct(env, tenant, rawId);
  const body = await readJson(request);
  const visible = bool01(body.is_visible);
  await env.DB.prepare('UPDATE products SET is_visible = ?, updated_at = ? WHERE id = ? AND tenant_id = ?')
    .bind(visible, nowIso(), current.id, tenant.id).run();
  return json({ product: { ...current, is_visible: visible } });
}

async function handleMe(request, env, tenant) {
  await touchPresence(env, tenant.id).catch(() => {});
  const [settings, products] = await Promise.all([loadSettings(env, tenant.id), loadProducts(env, tenant.id)]);
  return json({
    tenant: tenantPrivate(tenant),
    settings,
    products,
    store_url: `${publicBase(request, env)}/s/${tenant.id}`,
  });
}

async function handleProfile(request, env, tenant) {
  assertCanEdit(tenant);
  const body = await readJson(request);
  const data = {
    store_name: text(body.store_name, 80, 'Nome da loja', { required: true }),
    owner_name: text(body.owner_name, 80, 'Seu nome'),
    whatsapp: whatsapp(body.whatsapp, { required: true }),
    avatar_url: httpUrl(body.avatar_url, 'Foto/logo', { allowData: true }),
    theme_color: color(body.theme_color, tenant.theme_color),
  };
  const ts = nowIso();
  await env.DB.prepare(
    `UPDATE tenants SET store_name = ?, owner_name = ?, whatsapp = ?, avatar_url = ?, theme_color = ?, updated_at = ?
     WHERE id = ?`,
  ).bind(data.store_name, data.owner_name, data.whatsapp, data.avatar_url, data.theme_color, ts, tenant.id).run();
  if (tenant.avatar_url && tenant.avatar_url !== data.avatar_url) await deleteImage(env, tenant.avatar_url, tenant.id);
  return json({ tenant: tenantPrivate({ ...tenant, ...data, updated_at: ts }) });
}

async function handleSettings(request, env, tenant) {
  assertCanEdit(tenant);
  const body = await readJson(request);
  const current = await loadSettings(env, tenant.id);
  const pick = (key) => (body[key] === undefined ? current[key] : body[key]);
  const settings = {
    show_prices: bool01(pick('show_prices')),
    show_stock_warning: bool01(pick('show_stock_warning')),
    view_mode: pick('view_mode') === 'list' ? 'list' : 'grid',
    show_banner: bool01(pick('show_banner')),
    share_message: text(pick('share_message'), 600, 'Mensagem pronta'),
  };
  await env.DB.prepare(
    `INSERT INTO tenant_settings (tenant_id, show_prices, show_stock_warning, view_mode, show_banner, share_message)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (tenant_id) DO UPDATE SET
       show_prices = excluded.show_prices,
       show_stock_warning = excluded.show_stock_warning,
       view_mode = excluded.view_mode,
       show_banner = excluded.show_banner,
       share_message = excluded.share_message`,
  ).bind(tenant.id, settings.show_prices, settings.show_stock_warning, settings.view_mode, settings.show_banner, settings.share_message).run();
  return json({ settings });
}

async function handlePassword(request, env, tenant) {
  const body = await readJson(request);
  if (!(await verifyPassword(String(body.current_password || ''), tenant.password_hash))) {
    throw new HttpError(400, 'A senha atual está incorreta.');
  }
  const hash = await hashPassword(password(body.new_password, 'Nova senha'));
  await env.DB.prepare('UPDATE tenants SET password_hash = ?, updated_at = ? WHERE id = ?')
    .bind(hash, nowIso(), tenant.id).run();
  return json({ ok: true, token: await signToken(env, { ...tenant, password_hash: hash }) });
}

async function handleUpload(request, env, tenant) {
  assertCanEdit(tenant);
  if (!env.IMAGES) throw new HttpError(501, 'Armazenamento de imagens (R2) não configurado.', { code: 'no_r2' });
  const type = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  const ext = UPLOAD_TYPES[type];
  if (!ext) throw new HttpError(415, 'Envie uma imagem JPG, PNG ou WEBP.');
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > MAX_UPLOAD_BYTES) throw new HttpError(413, 'Imagem grande demais (máx. 3 MB).');
  const buffer = await request.arrayBuffer();
  if (!buffer.byteLength) throw new HttpError(400, 'Imagem vazia.');
  if (buffer.byteLength > MAX_UPLOAD_BYTES) throw new HttpError(413, 'Imagem grande demais (máx. 3 MB).');
  const key = `${tenant.id}/${Date.now().toString(36)}-${b64u(crypto.getRandomValues(new Uint8Array(6)))}.${ext}`;
  await env.IMAGES.put(key, buffer, { httpMetadata: { contentType: type, cacheControl: 'public, max-age=31536000, immutable' } });
  return json({ url: `${publicBase(request, env)}/api/images/${key}` }, 201);
}

async function getOwnedProduct(env, tenant, rawId) {
  const id = Number.parseInt(rawId, 10);
  if (!Number.isInteger(id) || id <= 0) throw new HttpError(404, 'Produto não encontrado.');
  const product = await env.DB.prepare('SELECT * FROM products WHERE id = ? AND tenant_id = ?').bind(id, tenant.id).first();
  if (!product) throw new HttpError(404, 'Produto não encontrado.');
  return product;
}

async function handleCreateProduct(request, env, tenant) {
  assertCanEdit(tenant);
  const p = productInput(await readJson(request));
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM products WHERE tenant_id = ?').bind(tenant.id).first('n');
  if (Number(count) >= MAX_PRODUCTS_PER_TENANT) {
    throw new HttpError(400, `Limite de ${MAX_PRODUCTS_PER_TENANT} produtos atingido.`);
  }
  const ts = nowIso();
  const row = await env.DB.prepare(
    `INSERT INTO products (tenant_id, title, description, price, image_url, affiliate_link, platform,
                           is_physical, delivery_cities, sort_order, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     RETURNING *`,
  ).bind(
    tenant.id, p.title, p.description, p.price, p.image_url, p.affiliate_link, p.platform,
    p.is_physical, p.delivery_cities, p.sort_order, ts, ts,
  ).first();
  return json({ product: row }, 201);
}

async function handleUpdateProduct(request, env, tenant, rawId) {
  assertCanEdit(tenant);
  const current = await getOwnedProduct(env, tenant, rawId);
  const p = productInput(await readJson(request));
  const row = await env.DB.prepare(
    `UPDATE products SET title = ?, description = ?, price = ?, image_url = ?, affiliate_link = ?, platform = ?,
                         is_physical = ?, delivery_cities = ?, sort_order = ?, updated_at = ?
     WHERE id = ? AND tenant_id = ?
     RETURNING *`,
  ).bind(
    p.title, p.description, p.price, p.image_url, p.affiliate_link, p.platform,
    p.is_physical, p.delivery_cities, p.sort_order, nowIso(), current.id, tenant.id,
  ).first();
  if (current.image_url && current.image_url !== p.image_url) await deleteImage(env, current.image_url, tenant.id);
  return json({ product: row });
}

async function handleDeleteProduct(env, tenant, rawId) {
  // Excluir continua liberado mesmo com o teste vencido.
  const current = await getOwnedProduct(env, tenant, rawId);
  await env.DB.prepare('DELETE FROM products WHERE id = ? AND tenant_id = ?').bind(current.id, tenant.id).run();
  await deleteImage(env, current.image_url, tenant.id);
  return json({ ok: true });
}

/* ------------------------------------------------------------------ */
/* Handlers Master                                                     */
/* ------------------------------------------------------------------ */

async function handleAdminList(request, env) {
  await expireLapsedTenants(env);
  const { results } = await env.DB.prepare(
    `SELECT t.*, (SELECT COUNT(*) FROM products p WHERE p.tenant_id = t.id) AS product_count
       FROM tenants t ORDER BY t.created_at DESC`,
  ).all();
  const base = publicBase(request, env);
  const tenants = (results || []).map((t) => ({
    ...tenantPrivate(t),
    product_count: Number(t.product_count || 0),
    store_url: `${base}/s/${t.id}`,
  }));
  const dayAgo = Date.now() - DAY_MS;
  const stats = {
    total: tenants.length,
    trial: tenants.filter((t) => t.status === 'trial').length,
    active: tenants.filter((t) => t.status === 'active').length,
    expired: tenants.filter((t) => t.status === 'expired').length,
    online: tenants.filter((t) => t.online).length,
    active_today: tenants.filter((t) => t.last_seen_at && Date.parse(t.last_seen_at) >= dayAgo).length,
    with_products: tenants.filter((t) => t.product_count > 0).length,
    products: tenants.reduce((sum, t) => sum + t.product_count, 0),
    views: tenants.reduce((sum, t) => sum + t.views, 0),
    new_7d: tenants.filter((t) => Date.parse(t.created_at) >= Date.now() - 7 * DAY_MS).length,
  };
  return json({ tenants, stats, plan_price: env.PLAN_PRICE || '19,90', trial_days: trialDays(env), server_time: nowIso() });
}

async function handleAdminConfigGet(env) {
  const cfg = await getConfig(env);
  return json({
    landing_video_url: cfg.landing_video_url || '',
    support_whatsapp: cfg.support_whatsapp || env.SUPPORT_WHATSAPP || '',
    master_password_source: env.MASTER_PASSWORD ? 'secret' : cfg.master_hash ? 'custom' : 'default',
  });
}

async function handleAdminConfigPut(request, env) {
  const body = await readJson(request);
  if (body.landing_video_url !== undefined) {
    const v = String(body.landing_video_url || '').trim();
    if (v && !videoEmbed(v)) throw new HttpError(400, 'Link de vídeo inválido. Use um link do YouTube, Vimeo ou um arquivo .mp4 (https).');
    await setConfig(env, 'landing_video_url', v);
  }
  if (body.support_whatsapp !== undefined) {
    await setConfig(env, 'support_whatsapp', whatsapp(body.support_whatsapp));
  }
  if (body.new_master_password !== undefined && String(body.new_master_password) !== '') {
    if (env.MASTER_PASSWORD) {
      throw new HttpError(400, 'A senha Master está fixada no Cloudflare (secret MASTER_PASSWORD). Altere por lá.');
    }
    await setConfig(env, 'master_hash', await hashPassword(password(body.new_master_password, 'Nova senha Master')));
  }
  return handleAdminConfigGet(env);
}

async function createTenant(request, env, body) {
  const storeName = text(body.store_name, 80, 'Nome da loja', { required: true });
  const id = storeSlug(body.id ? slugify(body.id) : slugify(storeName));
  const data = {
    id,
    store_name: storeName,
    owner_name: text(body.owner_name, 80, 'Seu nome'),
    whatsapp: whatsapp(body.whatsapp, { required: true }),
    avatar_url: httpUrl(body.avatar_url, 'Foto/logo'),
    theme_color: color(body.theme_color),
    password_hash: await hashPassword(password(body.password)),
  };
  const exists = await env.DB.prepare('SELECT 1 FROM tenants WHERE id = ?').bind(id).first();
  if (exists) throw new HttpError(409, `O endereço "${id}" já está em uso. Escolha outro.`, { code: 'slug_taken' });

  const createdMs = Date.now();
  const createdAt = new Date(createdMs).toISOString();
  const trialEndsAt = addDays(createdMs, trialDays(env)); // 7 dias grátis automáticos

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO tenants (id, store_name, owner_name, whatsapp, avatar_url, theme_color, password_hash,
                              status, trial_ends_at, paid_until, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'trial', ?, NULL, ?, ?)`,
      ).bind(
        data.id, data.store_name, data.owner_name, data.whatsapp, data.avatar_url, data.theme_color,
        data.password_hash, trialEndsAt, createdAt, createdAt,
      ),
      env.DB.prepare(
        'INSERT INTO tenant_settings (tenant_id, show_prices, show_stock_warning, view_mode) VALUES (?, 1, 1, ?)',
      ).bind(data.id, 'grid'),
    ]);
  } catch (err) {
    if (/UNIQUE|PRIMARY/i.test(String(err && err.message))) {
      throw new HttpError(409, `O endereço "${id}" já está em uso. Escolha outro.`, { code: 'slug_taken' });
    }
    throw err;
  }
  return env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(id).first();
}

async function handleAdminCreate(request, env) {
  const tenant = await createTenant(request, env, await readJson(request));
  return json({
    tenant: { ...tenantPrivate(tenant), product_count: 0, store_url: `${publicBase(request, env)}/s/${tenant.id}` },
  }, 201);
}

async function handleAdminPatch(request, env, rawId) {
  const id = String(rawId || '').toLowerCase();
  const tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(id).first();
  if (!tenant) throw new HttpError(404, 'Loja não encontrada.');
  const body = await readJson(request);
  const ts = nowIso();
  const now = Date.now();

  switch (body.action) {
    case 'activate': {
      // Soma os dias ao que ainda resta do plano pago (renovação não perde dias).
      const days = clampInt(body.days, 1, 3650, 30);
      const current = tenant.status === 'active' && tenant.paid_until ? Date.parse(tenant.paid_until) : 0;
      const paidUntil = addDays(Math.max(now, current), days);
      await env.DB.prepare("UPDATE tenants SET status = 'active', paid_until = ?, updated_at = ? WHERE id = ?")
        .bind(paidUntil, ts, id).run();
      break;
    }
    case 'extend_trial': {
      const days = clampInt(body.days, 1, 365, 7);
      const current = Date.parse(tenant.trial_ends_at) || 0;
      const trialEndsAt = addDays(Math.max(now, current), days);
      await env.DB.prepare("UPDATE tenants SET status = 'trial', trial_ends_at = ?, updated_at = ? WHERE id = ?")
        .bind(trialEndsAt, ts, id).run();
      break;
    }
    case 'expire':
      await env.DB.prepare("UPDATE tenants SET status = 'expired', updated_at = ? WHERE id = ?").bind(ts, id).run();
      break;
    case 'reset_password': {
      const hash = await hashPassword(password(body.password, 'Nova senha'));
      await env.DB.prepare('UPDATE tenants SET password_hash = ?, updated_at = ? WHERE id = ?').bind(hash, ts, id).run();
      break;
    }
    case 'update': {
      const storeName = text(body.store_name ?? tenant.store_name, 80, 'Nome da loja', { required: true });
      const ownerName = text(body.owner_name ?? tenant.owner_name, 80, 'Nome do responsável');
      const phone = whatsapp(body.whatsapp ?? tenant.whatsapp, { required: true });
      await env.DB.prepare('UPDATE tenants SET store_name = ?, owner_name = ?, whatsapp = ?, updated_at = ? WHERE id = ?')
        .bind(storeName, ownerName, phone, ts, id).run();
      break;
    }
    default:
      throw new HttpError(400, 'Ação inválida.');
  }

  const updated = await env.DB.prepare(
    'SELECT t.*, (SELECT COUNT(*) FROM products p WHERE p.tenant_id = t.id) AS product_count FROM tenants t WHERE t.id = ?',
  ).bind(id).first();
  return json({
    tenant: {
      ...tenantPrivate(updated),
      product_count: Number(updated.product_count || 0),
      store_url: `${publicBase(request, env)}/s/${id}`,
    },
  });
}

async function handleAdminDelete(env, rawId) {
  const id = String(rawId || '').toLowerCase();
  const exists = await env.DB.prepare('SELECT 1 FROM tenants WHERE id = ?').bind(id).first();
  if (!exists) throw new HttpError(404, 'Loja não encontrada.');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM products WHERE tenant_id = ?').bind(id),
    env.DB.prepare('DELETE FROM tenant_settings WHERE tenant_id = ?').bind(id),
    env.DB.prepare('DELETE FROM tenants WHERE id = ?').bind(id),
  ]);
  await deleteAllTenantImages(env, id);
  return json({ ok: true });
}

/* ------------------------------------------------------------------ */
/* Roteador                                                            */
/* ------------------------------------------------------------------ */

async function routeApi(request, env, path) {
  const method = request.method;
  let m;

  if (path === '/api/health' && method === 'GET') return json({ ok: true, time: nowIso() });
  await ensureSchema(env);
  if (path === '/api/config' && method === 'GET') return handleConfig(request, env);
  if ((m = path.match(/^\/api\/store\/([^/]+)$/)) && method === 'GET') return handleStore(env, decodeURIComponent(m[1]));
  if ((m = path.match(/^\/api\/images\/(.+)$/)) && method === 'GET') return handleImage(env, decodeURIComponent(m[1]));
  if (path === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
  if (path === '/api/auth/register' && method === 'POST') return handleRegister(request, env);
  if (path === '/api/auth/check-slug' && method === 'GET') return handleCheckSlug(env, new URL(request.url));

  if (path === '/api/me' || path.startsWith('/api/me/')) {
    const tenant = await requireTenant(request, env);
    if (path === '/api/me' && method === 'GET') return handleMe(request, env, tenant);
    if (path === '/api/me/ping' && method === 'POST') return handlePing(env, tenant);
    if (path === '/api/me/profile' && method === 'PUT') return handleProfile(request, env, tenant);
    if (path === '/api/me/settings' && method === 'PUT') return handleSettings(request, env, tenant);
    if (path === '/api/me/password' && method === 'PUT') return handlePassword(request, env, tenant);
    if (path === '/api/me/upload' && method === 'POST') return handleUpload(request, env, tenant);
    if (path === '/api/me/products' && method === 'POST') return handleCreateProduct(request, env, tenant);
    if ((m = path.match(/^\/api\/me\/products\/(\d+)\/visibility$/)) && method === 'PATCH') {
      return handleVisibility(request, env, tenant, m[1]);
    }
    if ((m = path.match(/^\/api\/me\/products\/(\d+)$/))) {
      if (method === 'PUT') return handleUpdateProduct(request, env, tenant, m[1]);
      if (method === 'DELETE') return handleDeleteProduct(env, tenant, m[1]);
    }
    throw new HttpError(404, 'Rota não encontrada.');
  }

  if (path === '/api/admin' || path.startsWith('/api/admin/')) {
    await requireMaster(request, env);
    if (path === '/api/admin/tenants' && method === 'GET') return handleAdminList(request, env);
    if (path === '/api/admin/tenants' && method === 'POST') return handleAdminCreate(request, env);
    if (path === '/api/admin/config' && method === 'GET') return handleAdminConfigGet(env);
    if (path === '/api/admin/config' && method === 'PUT') return handleAdminConfigPut(request, env);
    if ((m = path.match(/^\/api\/admin\/tenants\/([^/]+)$/))) {
      if (method === 'PATCH') return handleAdminPatch(request, env, decodeURIComponent(m[1]));
      if (method === 'DELETE') return handleAdminDelete(env, decodeURIComponent(m[1]));
    }
    throw new HttpError(404, 'Rota não encontrada.');
  }

  throw new HttpError(404, 'Rota não encontrada.');
}

// Texto seguro para atributos/meta (sem aspas nem tags).
const metaText = (value, max) => String(value || '').replace(/["<>\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const isHttpUrl = (value) => /^https?:\/\//i.test(String(value || ''));

async function storeMeta(env, slug, productId) {
  const t = await env.DB.prepare(
    'SELECT id, store_name, owner_name, avatar_url, theme_color, status, trial_ends_at, paid_until FROM tenants WHERE id = ?',
  ).bind(slug).first();
  if (!t) return null;
  const meta = {
    title: `${t.store_name} | Vitrine App`,
    description: `Confira os produtos selecionados por ${t.owner_name || t.store_name}.`,
    image: isHttpUrl(t.avatar_url) ? t.avatar_url : '',
    color: t.theme_color || '#16a6e0',
  };
  const pid = Number.parseInt(productId || '', 10);
  if (pid > 0 && t.status !== 'expired' && !isLapsed(t)) {
    const p = await env.DB.prepare('SELECT title, description, image_url FROM products WHERE id = ? AND tenant_id = ?')
      .bind(pid, t.id).first();
    if (p) {
      meta.title = `${p.title} | ${t.store_name}`;
      meta.description = p.description || meta.description;
      if (isHttpUrl(p.image_url)) meta.image = p.image_url;
    }
  }
  return meta;
}

async function serveAsset(request, env, url) {
  if (!env.ASSETS) return new Response('Not found', { status: 404 });

  // /s/<slug> → vitrine pública. O index.html lê o slug da URL; aqui só preenchemos
  // título e prévia (Open Graph) para o link ficar bonito no WhatsApp/Instagram.
  const m = url.pathname.match(/^\/s\/([a-z0-9-]{3,40})\/?$/i);
  if (!m) return env.ASSETS.fetch(request);

  const res = await env.ASSETS.fetch(new Request(new URL('/loja', url), request));
  const headers = new Headers(res.headers);
  headers.set('Cache-Control', 'public, max-age=60');
  const plain = new Response(res.body, { status: res.status, headers });
  if (!res.ok || !env.DB || typeof HTMLRewriter === 'undefined') return plain;

  let meta = null;
  try {
    await ensureSchema(env);
    meta = await storeMeta(env, m[1].toLowerCase(), url.searchParams.get('p'));
  } catch (err) {
    console.error('Falha ao montar prévia da vitrine:', err);
  }
  if (!meta) return plain;

  const title = metaText(meta.title, 120);
  const description = metaText(meta.description, 180);
  const setContent = (value) => ({ element(el) { el.setAttribute('content', value); } });
  let rewriter = new HTMLRewriter()
    .on('title', { element(el) { el.setInnerContent(title); } })
    .on('meta[name="description"]', setContent(description))
    .on('meta[property="og:title"]', setContent(title))
    .on('meta[property="og:description"]', setContent(description))
    .on('meta[property="og:url"]', setContent(metaText(url.toString(), 500)))
    .on('meta[name="theme-color"]', setContent(metaText(meta.color, 7)));
  if (meta.image) rewriter = rewriter.on('meta[property="og:image"]', setContent(metaText(meta.image, 1000)));
  return rewriter.transform(plain);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = corsHeaders(env);

    if (!url.pathname.startsWith('/api/')) return serveAsset(request, env, url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    let response;
    try {
      if (!env.DB) throw new HttpError(500, 'Banco D1 (binding DB) não configurado.');
      response = await routeApi(request, env, url.pathname.replace(/\/+$/, '') || '/');
    } catch (err) {
      if (err instanceof HttpError) {
        response = json({ error: err.message, ...err.extra }, err.status);
      } else {
        console.error('Erro inesperado:', err && err.stack ? err.stack : err);
        response = json({ error: 'Erro interno. Tente novamente em instantes.' }, 500);
      }
    }
    for (const [k, v] of Object.entries(cors)) response.headers.set(k, v);
    return response;
  },
};
