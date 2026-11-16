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
 *   POST   /api/auth/login                 { login: WhatsApp ou endereço da loja, password }
 *
 * Rotas do lojista (Authorization: Bearer <token>)
 *   GET    /api/me
 *   POST   /api/me/ping                    presença (online no Master)
 *   POST   /api/me/lookup                  { url } → nome, preço e foto (cota: 15 buscas/hora por lojista)
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
 *   PUT    /api/admin/config               vídeo, WhatsApp de suporte, senha Master, chaves da Shopee
 *   POST   /api/admin/integrations/test    { url } testa a busca automática de produto
 *   POST   /api/admin/ml/start             gera o link para conectar a conta do Mercado Livre
 *   GET    /api/admin/ml/callback          retorno da autorização do Mercado Livre (público, validado por state)
 *   POST   /api/admin/ml/disconnect
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

const PASSWORD_MIN = 4; // senha do lojista: mínimo 4 dígitos/caracteres (Master continua com 6)

function password(value, field = 'Senha', min = PASSWORD_MIN) {
  const v = String(value ?? '');
  if (v.length < min) throw new HttpError(400, `${field}: mínimo de ${min} caracteres.`);
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

/* ------------------------------------------------------------------ */
/* Proteção contra tentativas de senha (senhas de 4 dígitos)          */
/* ------------------------------------------------------------------ */

const clientIp = (request) => request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'local';

async function checkLocked(env, keys) {
  const now = nowIso();
  for (const key of keys) {
    const row = await env.DB.prepare('SELECT locked_until FROM login_attempts WHERE key = ?').bind(key).first();
    if (row && row.locked_until && row.locked_until > now) {
      const min = Math.max(1, Math.ceil((Date.parse(row.locked_until) - Date.now()) / 60_000));
      throw new HttpError(429, `Muitas tentativas erradas. Por segurança, tente de novo em ${min} min.`, { code: 'locked' });
    }
  }
}

// Conta erros numa janela; ao passar do limite, bloqueia por alguns minutos.
async function registerFail(env, key, { max, windowMin, lockMin }) {
  const now = Date.now();
  const row = await env.DB.prepare('SELECT fails, window_start FROM login_attempts WHERE key = ?').bind(key).first();
  const inWindow = row && now - Date.parse(row.window_start) < windowMin * 60_000;
  const fails = inWindow ? Number(row.fails) + 1 : 1;
  const windowStart = inWindow ? row.window_start : new Date(now).toISOString();
  const lockedUntil = fails >= max ? new Date(now + lockMin * 60_000).toISOString() : null;
  await env.DB.prepare(
    `INSERT INTO login_attempts (key, fails, window_start, locked_until) VALUES (?, ?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET fails = excluded.fails, window_start = excluded.window_start, locked_until = excluded.locked_until`,
  ).bind(key, lockedUntil ? 0 : fails, lockedUntil ? new Date(now).toISOString() : windowStart, lockedUntil).run();
  if (Math.random() < 0.05) {
    await env.DB.prepare('DELETE FROM login_attempts WHERE window_start < ? AND (locked_until IS NULL OR locked_until < ?)')
      .bind(new Date(now - DAY_MS).toISOString(), new Date(now).toISOString()).run();
  }
}

async function clearFails(env, keys) {
  for (const key of keys) await env.DB.prepare('DELETE FROM login_attempts WHERE key = ?').bind(key).run();
}

async function assertPhoneFree(env, phone, exceptId = null) {
  if (!phone) return;
  const other = await env.DB.prepare('SELECT id FROM tenants WHERE whatsapp = ? AND id <> ? LIMIT 1')
    .bind(phone, exceptId || '').first();
  if (other) throw new HttpError(409, 'Já existe uma conta com este WhatsApp. Use "Entrar" ou fale com o suporte.', { code: 'phone_taken' });
}

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
      await env.DB.prepare(
        'CREATE TABLE IF NOT EXISTS product_cache (key TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at TEXT NOT NULL)',
      ).run();
      await env.DB.prepare(
        'CREATE TABLE IF NOT EXISTS lookup_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, at TEXT NOT NULL)',
      ).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_lookup_usage ON lookup_usage (tenant_id, at)').run();
      await env.DB.prepare(
        'CREATE TABLE IF NOT EXISTS login_attempts (key TEXT PRIMARY KEY, fails INTEGER NOT NULL, window_start TEXT NOT NULL, locked_until TEXT)',
      ).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_tenants_whatsapp ON tenants (whatsapp)').run();
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

/* ------------------------------------------------------------------ */
/* Integrações: busca automática de produtos (API de afiliados)       */
/* ------------------------------------------------------------------ */

// Chaves de integração ficam cifradas (AES-GCM) no D1 e nunca voltam para o navegador.
async function configKey(env) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode('vitrine-config:' + (await sessionSecret(env))));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptValue(env, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await configKey(env), enc.encode(String(value)));
  return `${b64u(iv)}.${b64u(ct)}`;
}

async function decryptValue(env, stored) {
  if (!stored) return '';
  try {
    const [iv, ct] = String(stored).split('.');
    return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(iv) }, await configKey(env), unb64u(ct)));
  } catch {
    return '';
  }
}

async function shopeeCredentials(env, cfg) {
  const appId = String(env.SHOPEE_APP_ID || cfg.shopee_app_id || '').trim();
  const secret = String(env.SHOPEE_SECRET || (await decryptValue(env, cfg.shopee_secret)) || '').trim();
  return appId && secret ? { appId, secret } : null;
}

const SHOPEE_HOST = /(^|\.)(shopee\.com\.br|shope\.ee|shp\.ee)$/i;
const ML_HOST = /(^|\.)(mercadolivre\.com(\.br)?|mercadolibre\.com|meli\.la)$/i;

function detectPlatform(url) {
  const host = url.hostname.toLowerCase();
  if (SHOPEE_HOST.test(host)) return 'shopee';
  if (ML_HOST.test(host)) return 'mercadolivre';
  return null;
}

// Procura shopId/itemId em qualquer formato de link da Shopee (inclusive links aninhados/codificados).
function extractShopeeIds(text) {
  let s = String(text || '');
  for (let i = 0; i < 3; i++) {
    try { const d = decodeURIComponent(s); if (d === s) break; s = d; } catch { break; }
  }
  const patterns = [
    /-i\.(\d{3,})\.(\d{3,})/,
    /\/product\/(\d{3,})\/(\d{3,})/,
    /\/(?:[^/?#]+\/)?(\d{5,})\/(\d{5,})(?:[/?#]|$)/,
  ];
  for (const re of patterns) {
    const m = s.match(re);
    if (m) return { shopId: m[1], itemId: m[2] };
  }
  const shop = s.match(/shop_?id["=:\s]+(\d{3,})/i);
  const item = s.match(/item_?id["=:\s]+(\d{3,})/i);
  if (shop && item) return { shopId: shop[1], itemId: item[1] };
  return null;
}

// Segue links curtos (s.shopee.com.br/...) até achar o produto.
async function resolveShopeeIds(rawUrl) {
  let current = rawUrl;
  for (let hop = 0; hop < 6; hop++) {
    const ids = extractShopeeIds(current);
    if (ids) return ids;
    let res;
    try {
      res = await fetch(current, {
        redirect: 'manual',
        headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36', Accept: 'text/html' },
      });
    } catch {
      return null;
    }
    const location = res.headers.get('Location');
    if (location && res.status >= 300 && res.status < 400) {
      current = new URL(location, current).toString();
      continue;
    }
    if (res.ok) {
      const html = (await res.text()).slice(0, 300_000);
      return extractShopeeIds(html);
    }
    return null;
  }
  return extractShopeeIds(current);
}

async function shopeeGraphql(creds, query) {
  const payload = JSON.stringify({ query });
  const timestamp = Math.floor(Date.now() / 1000);
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(`${creds.appId}${timestamp}${payload}${creds.secret}`));
  const signature = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  let res;
  try {
    res = await fetch('https://open-api.affiliate.shopee.com.br/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `SHA256 Credential=${creds.appId}, Timestamp=${timestamp}, Signature=${signature}`,
      },
      body: payload,
    });
  } catch {
    throw new HttpError(502, 'Não foi possível falar com a Shopee agora. Tente de novo.');
  }
  const data = await res.json().catch(() => ({}));
  if (data.errors && data.errors.length) {
    const e = data.errors[0];
    const code = e.extensions && e.extensions.code;
    console.error('Shopee API:', JSON.stringify(data.errors).slice(0, 500));
    if (code === 10020 || /signature|auth|credential/i.test(e.message || '')) {
      throw new HttpError(502, 'A Shopee recusou as chaves da API. Confira o App ID e o Secret no Master.', { code: 'shopee_auth' });
    }
    if (code === 10030) throw new HttpError(429, 'Limite de consultas da Shopee atingido. Tente em alguns minutos.');
    throw new HttpError(502, `Shopee: ${String(e.message || 'erro na consulta').slice(0, 160)}`);
  }
  if (!res.ok) throw new HttpError(502, `A Shopee respondeu com erro ${res.status}.`);
  return data.data || {};
}

async function lookupShopee(env, creds, url) {
  const ids = await resolveShopeeIds(url);
  if (!ids) throw new HttpError(422, 'Não encontrei o produto neste link da Shopee. Confira se é o link de um produto.');
  const query = `{ productOfferV2(shopId: ${ids.shopId}, itemId: ${ids.itemId}, page: 1, limit: 1) {
    nodes { itemId shopId productName price priceMin priceMax imageUrl shopName ratingStar sales priceDiscountRate } } }`;
  const data = await shopeeGraphql(creds, query);
  const node = (((data.productOfferV2 || {}).nodes) || [])[0];
  if (!node) throw new HttpError(404, 'A Shopee não retornou este produto. Ele pode não participar do programa de afiliados.');
  const priceValue = Number(node.priceMin || node.price);
  return {
    platform: 'shopee',
    title: String(node.productName || '').slice(0, 120),
    price: Number.isFinite(priceValue) && priceValue > 0 ? Math.round(priceValue * 100) / 100 : null,
    price_max: Number(node.priceMax) || null,
    image_url: /^https?:\/\//.test(node.imageUrl || '') ? node.imageUrl : null,
    shop_name: node.shopName || null,
    rating: node.ratingStar ? Number(node.ratingStar) : null,
    sales: node.sales ? Number(node.sales) : null,
  };
}

/* ---------- Mercado Livre (OAuth: ML_CLIENT_ID / ML_CLIENT_SECRET) ---------- */

const ML_API = 'https://api.mercadolibre.com';
const mlConfigured = (env) => !!(env.ML_CLIENT_ID && env.ML_CLIENT_SECRET);
const mlRedirectUri = (request, env) => env.ML_REDIRECT_URI || `${publicBase(request, env)}/api/admin/ml/callback`;

async function mlTokenRequest(env, params) {
  let res;
  try {
    res = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ client_id: env.ML_CLIENT_ID, client_secret: env.ML_CLIENT_SECRET, ...params }).toString(),
    });
  } catch {
    throw new HttpError(502, 'Não foi possível falar com o Mercado Livre agora.');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    console.error('Mercado Livre token:', res.status, JSON.stringify(data).slice(0, 300));
    const msg = data.error === 'invalid_grant'
      ? 'A conexão com o Mercado Livre expirou. Conecte de novo no Master.'
      : `Mercado Livre recusou: ${String(data.message || data.error || res.status).slice(0, 120)}`;
    throw new HttpError(502, msg, { code: data.error === 'invalid_grant' ? 'ml_reconnect' : 'ml_error' });
  }
  return data;
}

async function mlSaveTokens(env, data) {
  await setConfig(env, 'ml_tokens', await encryptValue(env, JSON.stringify({
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: Date.now() + (Number(data.expires_in) || 21600) * 1000,
    user_id: data.user_id || null,
  })));
}

let mlRefreshing = null;
async function mlAccessToken(env, cfg) {
  if (!mlConfigured(env) || !cfg.ml_tokens) return null;
  const raw = await decryptValue(env, cfg.ml_tokens);
  if (!raw) return null;
  const tokens = JSON.parse(raw);
  if (tokens.expires_at - Date.now() > 5 * 60_000) return tokens.access_token;
  // Renova sozinho (o access token do ML dura 6 h; o refresh token só pode ser usado uma vez).
  if (!mlRefreshing) {
    mlRefreshing = (async () => {
      const fresh = await env.DB.prepare("SELECT value FROM app_config WHERE key = 'ml_tokens'").first('value');
      const current = JSON.parse((await decryptValue(env, fresh)) || '{}');
      if (current.expires_at - Date.now() > 5 * 60_000) return current.access_token;
      const data = await mlTokenRequest(env, { grant_type: 'refresh_token', refresh_token: current.refresh_token });
      await mlSaveTokens(env, data);
      return data.access_token;
    })().finally(() => { mlRefreshing = null; });
  }
  return mlRefreshing;
}

async function mlGet(token, path) {
  let res;
  try {
    res = await fetch(`${ML_API}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } });
  } catch {
    throw new HttpError(502, 'Não foi possível falar com o Mercado Livre agora.');
  }
  if (res.status === 404) return null;
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) throw new HttpError(502, 'A conexão com o Mercado Livre expirou. Conecte de novo no Master.', { code: 'ml_reconnect' });
  if (res.status === 429) throw new HttpError(429, 'Limite de consultas do Mercado Livre atingido. Tente em alguns minutos.');
  if (!res.ok) throw new HttpError(502, `Mercado Livre: ${String(data.message || res.status).slice(0, 120)}`);
  return data;
}

// Acha o código do anúncio (MLB...) ou do produto de catálogo (/p/MLB...) em qualquer formato de link.
function extractMlIds(text) {
  let s = String(text || '');
  for (let i = 0; i < 3; i++) {
    try { const d = decodeURIComponent(s); if (d === s) break; s = d; } catch { break; }
  }
  const wid = s.match(/[?&#](?:wid|item_id|itemId)=(MLB-?\d{6,})/i);
  const catalog = s.match(/\/p\/(MLB\d{5,})/i);
  const pathItem = s.match(/\/(MLB)-(\d{6,})/i) || s.match(/\/(MLB)(\d{6,})(?:[-_/?#"']|$)/i);
  const itemId = wid ? wid[1].replace('-', '').toUpperCase() : (!catalog && pathItem ? `MLB${pathItem[2]}` : null);
  const productId = catalog ? catalog[1].toUpperCase() : null;
  return itemId || productId ? { itemId, productId } : null;
}

async function resolveMlIds(rawUrl) {
  let current = rawUrl;
  for (let hop = 0; hop < 6; hop++) {
    const ids = extractMlIds(current);
    if (ids) return ids;
    let res;
    try {
      res = await fetch(current, {
        redirect: 'manual',
        headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36', Accept: 'text/html' },
      });
    } catch {
      return null;
    }
    const location = res.headers.get('Location');
    if (location && res.status >= 300 && res.status < 400) {
      current = new URL(location, current).toString();
      continue;
    }
    if (res.ok) {
      const html = (await res.text()).slice(0, 400_000);
      const canonical = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)/i)
        || html.match(/<meta[^>]+property=["']og:url["'][^>]+content=["']([^"']+)/i);
      return extractMlIds(canonical ? canonical[1] : html);
    }
    return null;
  }
  return extractMlIds(current);
}

const httpsImage = (u) => (u ? String(u).replace(/^http:\/\//i, 'https://') : null);

async function lookupMercadoLivre(env, token, url) {
  const ids = await resolveMlIds(url);
  if (!ids) throw new HttpError(422, 'Não encontrei o produto neste link do Mercado Livre. Confira se é o link de um produto.');
  if (ids.itemId) {
    const item = await mlGet(token, `/items/${ids.itemId}`);
    if (item && item.title) {
      return {
        platform: 'mercadolivre',
        title: String(item.title).slice(0, 120),
        price: Number(item.price) > 0 ? Number(item.price) : null,
        image_url: httpsImage((item.pictures && item.pictures[0] && (item.pictures[0].secure_url || item.pictures[0].url)) || item.thumbnail),
        shop_name: null,
      };
    }
  }
  if (ids.productId) {
    const prod = await mlGet(token, `/products/${ids.productId}`);
    if (prod && prod.name) {
      const price = prod.buy_box_winner && Number(prod.buy_box_winner.price);
      return {
        platform: 'mercadolivre',
        title: String(prod.name).slice(0, 120),
        price: price > 0 ? price : null,
        image_url: httpsImage(prod.pictures && prod.pictures[0] && (prod.pictures[0].secure_url || prod.pictures[0].url)),
        shop_name: null,
      };
    }
  }
  throw new HttpError(404, 'O Mercado Livre não retornou este produto. Ele pode ter sido pausado ou removido.');
}

async function handleMlStart(request, env) {
  if (!mlConfigured(env)) throw new HttpError(400, 'Crie os secrets ML_CLIENT_ID e ML_CLIENT_SECRET no Cloudflare e publique de novo.');
  const state = b64u(crypto.getRandomValues(new Uint8Array(24)));
  await setConfig(env, 'ml_oauth_state', JSON.stringify({ state, exp: Date.now() + 15 * 60_000 }));
  const auth = new URL('https://auth.mercadolivre.com.br/authorization');
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('client_id', env.ML_CLIENT_ID);
  auth.searchParams.set('redirect_uri', mlRedirectUri(request, env));
  auth.searchParams.set('state', state);
  return json({ url: auth.toString(), redirect_uri: mlRedirectUri(request, env) });
}

async function handleMlCallback(request, env) {
  const url = new URL(request.url);
  const back = (status, msg) => new Response(null, {
    status: 302,
    headers: {
      Location: `${publicBase(request, env)}/admin.html?ml=${status}${msg ? `&msg=${encodeURIComponent(msg)}` : ''}`,
      'Cache-Control': 'no-store',
    },
  });
  try {
    if (url.searchParams.get('error')) return back('erro', url.searchParams.get('error_description') || 'Autorização cancelada.');
    const saved = JSON.parse((await env.DB.prepare("SELECT value FROM app_config WHERE key = 'ml_oauth_state'").first('value')) || '{}');
    const state = url.searchParams.get('state') || '';
    if (!saved.state || saved.exp < Date.now() || !timingSafeEqual(enc.encode(saved.state), enc.encode(state))) {
      return back('erro', 'Link de conexão expirado. Tente conectar de novo.');
    }
    await env.DB.prepare("DELETE FROM app_config WHERE key = 'ml_oauth_state'").run();
    const code = url.searchParams.get('code');
    if (!code) return back('erro', 'O Mercado Livre não enviou a autorização.');
    const data = await mlTokenRequest(env, { grant_type: 'authorization_code', code, redirect_uri: mlRedirectUri(request, env) });
    await mlSaveTokens(env, data);
    try {
      const me = await mlGet(data.access_token, '/users/me');
      if (me && me.nickname) await setConfig(env, 'ml_nickname', me.nickname);
    } catch { /* apelido é opcional */ }
    return back('ok');
  } catch (err) {
    return back('erro', err instanceof HttpError ? err.message : 'Falha ao conectar com o Mercado Livre.');
  }
}

// Cota do plano básico: buscas automáticas por lojista a cada hora (padrão 15).
// Conta no banco, então vale para todos os servidores. Resultados do cache não gastam cota.
const lookupLimit = (env) => clampInt(env.LOOKUP_LIMIT_PER_HOUR, 1, 1000, 15);

async function lookupQuota(env, tenantId) {
  const since = new Date(Date.now() - 3_600_000).toISOString();
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS used, MIN(at) AS oldest FROM lookup_usage WHERE tenant_id = ? AND at > ?',
  ).bind(tenantId, since).first();
  const limit = lookupLimit(env);
  const used = Number(row && row.used) || 0;
  const resetMin = row && row.oldest ? Math.max(1, Math.ceil((Date.parse(row.oldest) + 3_600_000 - Date.now()) / 60_000)) : 60;
  return { limit, used, remaining: Math.max(0, limit - used), reset_minutes: used ? resetMin : null };
}

async function lookupProduct(env, rawUrl, { useCache = true, tenantId = null } = {}) {
  const link = httpUrl(rawUrl, 'Link', { required: true });
  const url = new URL(link);
  const platform = detectPlatform(url);
  if (!platform) throw new HttpError(422, 'A busca automática funciona com links da Shopee e do Mercado Livre.');
  const cacheKey = `${platform}:${url.toString()}`;
  if (useCache) {
    const hit = await env.DB.prepare('SELECT data, fetched_at FROM product_cache WHERE key = ?').bind(cacheKey).first();
    if (hit && Date.now() - Date.parse(hit.fetched_at) < 6 * 3_600_000) return { ...JSON.parse(hit.data), cached: true };
  }
  if (tenantId) {
    const quota = await lookupQuota(env, tenantId);
    if (quota.remaining <= 0) {
      throw new HttpError(429, `Você usou as ${quota.limit} buscas automáticas desta hora. Libera de novo em ${quota.reset_minutes} min — enquanto isso, preencha manualmente.`, { code: 'quota', quota });
    }
    await env.DB.batch([
      env.DB.prepare('INSERT INTO lookup_usage (tenant_id, at) VALUES (?, ?)').bind(tenantId, nowIso()),
      env.DB.prepare('DELETE FROM lookup_usage WHERE at < ?').bind(new Date(Date.now() - 2 * 3_600_000).toISOString()),
    ]);
  }
  const cfg = await getConfig(env);
  let result;
  if (platform === 'shopee') {
    const creds = await shopeeCredentials(env, cfg);
    if (!creds) throw new HttpError(501, 'A busca automática da Shopee ainda não foi ativada pelo administrador.', { code: 'not_configured' });
    result = await lookupShopee(env, creds, link);
  } else {
    const token = await mlAccessToken(env, cfg);
    if (!token) throw new HttpError(501, 'A busca automática do Mercado Livre ainda não foi ativada pelo administrador.', { code: 'not_configured' });
    result = await lookupMercadoLivre(env, token, link);
  }
  await env.DB.prepare(
    `INSERT INTO product_cache (key, data, fetched_at) VALUES (?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at`,
  ).bind(cacheKey, JSON.stringify(result), nowIso()).run();
  return result;
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
  const lockKey = `m:${clientIp(request)}`;
  await checkLocked(env, [lockKey]);
  let ok;
  if (env.MASTER_PASSWORD) {
    ok = timingSafeEqual(await sha256(given), await sha256(env.MASTER_PASSWORD));
  } else {
    const stored = await env.DB.prepare("SELECT value FROM app_config WHERE key = 'master_hash'").first('value');
    ok = stored
      ? await verifyPassword(given, stored)
      : timingSafeEqual(await sha256(given), await sha256(MASTER_DEFAULT_PASSWORD));
  }
  if (!ok) {
    await registerFail(env, lockKey, { max: 5, windowMin: 15, lockMin: 15 });
    throw new HttpError(401, 'Senha Master incorreta.');
  }
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
    lookup: { shopee: !!(await shopeeCredentials(env, cfg)), mercadolivre: mlConfigured(env) && !!cfg.ml_tokens },
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

// Entrada do lojista: pelo WhatsApp cadastrado (ou pelo endereço da loja) + senha.
async function handleLogin(request, env) {
  const body = await readJson(request);
  const raw = String(body.login ?? body.store_id ?? '').trim();
  const pw = String(body.password || '');
  const ip = clientIp(request);
  await checkLocked(env, [`ip:${ip}`]);

  let tenant = null;
  if (/[a-z]/i.test(raw)) {
    const id = raw.toLowerCase().replace(/^.*\/s\//, '').replace(/[^a-z0-9-]/g, '');
    if (SLUG_RE.test(id)) tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(id).first();
  } else {
    let phone = '';
    try { phone = whatsapp(raw); } catch { phone = ''; }
    if (phone) {
      const { results } = await env.DB.prepare('SELECT * FROM tenants WHERE whatsapp = ? ORDER BY created_at LIMIT 2').bind(phone).all();
      if (results && results.length > 1) {
        throw new HttpError(409, 'Há mais de uma loja com este WhatsApp. Entre com o endereço da loja (ex.: loja-do-joao).', { code: 'phone_multiple' });
      }
      tenant = results && results[0] ? results[0] : null;
    }
  }

  const keys = tenant ? [`t:${tenant.id}:${ip}`, `t:${tenant.id}`] : [];
  if (keys.length) await checkLocked(env, keys);
  const ok = await verifyPassword(pw, tenant ? tenant.password_hash : DUMMY_HASH);
  if (!tenant || !ok) {
    if (tenant) {
      await registerFail(env, keys[0], { max: 5, windowMin: 15, lockMin: 15 });
      await registerFail(env, keys[1], { max: 20, windowMin: 60, lockMin: 30 });
    } else {
      await registerFail(env, `ip:${ip}`, { max: 20, windowMin: 15, lockMin: 15 });
    }
    throw new HttpError(401, 'WhatsApp ou senha incorretos.');
  }
  await clearFails(env, keys);
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

async function handleLookup(request, env, tenant) {
  assertCanEdit(tenant);
  const body = await readJson(request);
  const product = await lookupProduct(env, body.url, { tenantId: tenant.id });
  return json({ product, quota: await lookupQuota(env, tenant.id) });
}

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
    lookup_quota: await lookupQuota(env, tenant.id),
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
  await assertPhoneFree(env, data.whatsapp, tenant.id);
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
    shopee_app_id: env.SHOPEE_APP_ID || cfg.shopee_app_id || '',
    shopee_secret_set: !!(env.SHOPEE_SECRET || cfg.shopee_secret),
    shopee_fixed: !!env.SHOPEE_APP_ID,
    ml_configured: mlConfigured(env),
    ml_connected: mlConfigured(env) && !!cfg.ml_tokens,
    ml_nickname: cfg.ml_nickname || null,
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
  if (body.shopee_app_id !== undefined) {
    const appId = String(body.shopee_app_id || '').trim();
    if (appId && !/^\d{3,20}$/.test(appId)) throw new HttpError(400, 'O App ID da Shopee deve conter só números.');
    await setConfig(env, 'shopee_app_id', appId);
  }
  if (body.shopee_secret !== undefined && String(body.shopee_secret).trim() !== '') {
    const secret = String(body.shopee_secret).trim();
    if (secret.length < 8 || secret.length > 200) throw new HttpError(400, 'Secret da Shopee inválido.');
    await setConfig(env, 'shopee_secret', await encryptValue(env, secret));
  }
  if (body.clear_shopee === true) {
    await env.DB.prepare("DELETE FROM app_config WHERE key IN ('shopee_app_id', 'shopee_secret')").run();
  }
  if (body.new_master_password !== undefined && String(body.new_master_password) !== '') {
    if (env.MASTER_PASSWORD) {
      throw new HttpError(400, 'A senha Master está fixada no Cloudflare (secret MASTER_PASSWORD). Altere por lá.');
    }
    await setConfig(env, 'master_hash', await hashPassword(password(body.new_master_password, 'Nova senha Master', 6)));
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
  await assertPhoneFree(env, data.whatsapp);

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
      await env.DB.prepare("DELETE FROM login_attempts WHERE key = ? OR key LIKE ?").bind(`t:${id}`, `t:${id}:%`).run();
      break;
    }
    case 'update': {
      const storeName = text(body.store_name ?? tenant.store_name, 80, 'Nome da loja', { required: true });
      const ownerName = text(body.owner_name ?? tenant.owner_name, 80, 'Nome do responsável');
      const phone = whatsapp(body.whatsapp ?? tenant.whatsapp, { required: true });
      await assertPhoneFree(env, phone, id);
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
    if (path === '/api/me/lookup' && method === 'POST') return handleLookup(request, env, tenant);
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

  if (path === '/api/admin/ml/callback' && method === 'GET') return handleMlCallback(request, env);

  if (path === '/api/admin' || path.startsWith('/api/admin/')) {
    await requireMaster(request, env);
    if (path === '/api/admin/ml/start' && method === 'POST') return handleMlStart(request, env);
    if (path === '/api/admin/ml/disconnect' && method === 'POST') {
      await env.DB.prepare("DELETE FROM app_config WHERE key IN ('ml_tokens', 'ml_nickname')").run();
      return json({ ok: true });
    }
    if (path === '/api/admin/tenants' && method === 'GET') return handleAdminList(request, env);
    if (path === '/api/admin/tenants' && method === 'POST') return handleAdminCreate(request, env);
    if (path === '/api/admin/config' && method === 'GET') return handleAdminConfigGet(env);
    if (path === '/api/admin/config' && method === 'PUT') return handleAdminConfigPut(request, env);
    if (path === '/api/admin/integrations/test' && method === 'POST') {
      const body = await readJson(request);
      return json({ product: await lookupProduct(env, body.url, { useCache: false }) });
    }
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
    // Respostas com cabeçalhos imutáveis (ex.: imagens do R2) são copiadas antes de receber o CORS.
    try {
      for (const [k, v] of Object.entries(cors)) response.headers.set(k, v);
    } catch {
      response = new Response(response.body, response);
      for (const [k, v] of Object.entries(cors)) response.headers.set(k, v);
    }
    return response;
  },
};
