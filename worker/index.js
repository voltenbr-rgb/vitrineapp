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
 *   POST   /api/admin/ml/affiliate         { link } lê os parâmetros de afiliado (matt_*) de um link seu
 *   POST   /api/admin/ml/search            { query, limit, sort, include, exclude } busca produtos e monta links
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
    show_price: body.show_price === undefined ? 1 : bool01(body.show_price),
    original_price: price(body.original_price),
    // Categoria livre, com a primeira letra maiúscula (ex.: "Cozinha", "Moda feminina").
    category: (() => {
      const c = text(body.category, 40, 'Categoria').replace(/\s+/g, ' ');
      return c ? c.charAt(0).toUpperCase() + c.slice(1) : '';
    })(),
  };
  // Preço antigo (De) só faz sentido se for maior que o preço atual.
  if (product.original_price !== null && (product.price === null || product.original_price <= product.price)) product.original_price = null;
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

async function assertPhoneFree(env, phone, exceptAccountId = null) {
  const row = await env.DB.prepare('SELECT id FROM accounts WHERE whatsapp = ? AND id IS NOT ?').bind(phone, exceptAccountId).first();
  if (row) throw new HttpError(409, 'Este WhatsApp já tem uma conta. Entre com ele ou use a opção "Esqueci a senha".', { code: 'phone_taken' });
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
      if (!pc.has('show_price')) alters.push('ALTER TABLE products ADD COLUMN show_price INTEGER NOT NULL DEFAULT 1');
      if (!pc.has('original_price')) alters.push('ALTER TABLE products ADD COLUMN original_price REAL');
      if (!pc.has('category')) alters.push("ALTER TABLE products ADD COLUMN category TEXT NOT NULL DEFAULT ''");
      if (!sc.has('show_banner')) alters.push('ALTER TABLE tenant_settings ADD COLUMN show_banner INTEGER NOT NULL DEFAULT 1');
      if (!sc.has('share_message')) alters.push("ALTER TABLE tenant_settings ADD COLUMN share_message TEXT NOT NULL DEFAULT ''");
      if (!sc.has('offer_template')) alters.push('ALTER TABLE tenant_settings ADD COLUMN offer_template INTEGER NOT NULL DEFAULT 1');
      if (!tc.has('account_id')) alters.push('ALTER TABLE tenants ADD COLUMN account_id INTEGER');
      if (!tc.has('cover_url')) alters.push('ALTER TABLE tenants ADD COLUMN cover_url TEXT');
      if (!sc.has('theme_mode')) alters.push("ALTER TABLE tenant_settings ADD COLUMN theme_mode TEXT NOT NULL DEFAULT 'light'");
      if (!sc.has('card_tone')) alters.push("ALTER TABLE tenant_settings ADD COLUMN card_tone TEXT NOT NULL DEFAULT 'white'");
      if (!sc.has('show_whatsapp')) alters.push('ALTER TABLE tenant_settings ADD COLUMN show_whatsapp INTEGER NOT NULL DEFAULT 1');
      if (!sc.has('store_mode')) alters.push("ALTER TABLE tenant_settings ADD COLUMN store_mode TEXT NOT NULL DEFAULT 'mixed'");
      if (!sc.has('offer_templates')) alters.push("ALTER TABLE tenant_settings ADD COLUMN offer_templates TEXT NOT NULL DEFAULT ''");
      for (const sql of alters) {
        try {
          await env.DB.prepare(sql).run();
        } catch (err) {
          if (!/duplicate column/i.test(String(err && err.message))) throw err;
        }
      }
      // Conta (dono, login, plano e pagamento) separada das lojas: uma conta pode ter várias lojas.
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS accounts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          owner_name TEXT NOT NULL DEFAULT '',
          whatsapp TEXT NOT NULL DEFAULT '',
          password_hash TEXT NOT NULL,
          plan TEXT NOT NULL DEFAULT 'basic',
          status TEXT NOT NULL DEFAULT 'trial',
          trial_ends_at TEXT NOT NULL,
          paid_until TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          last_seen_at TEXT,
          last_login_at TEXT,
          legacy_tenant_id TEXT
        )`,
      ).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_accounts_whatsapp ON accounts (whatsapp)').run();
      // Pagamentos do Mercado Pago (Pix ou cartão). "applied" garante que cada pagamento ativa o plano uma vez só.
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS payments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          account_id INTEGER NOT NULL,
          plan TEXT NOT NULL,
          days INTEGER NOT NULL DEFAULT 30,
          amount REAL NOT NULL,
          method TEXT NOT NULL,
          mp_id TEXT,
          ref TEXT NOT NULL UNIQUE,
          status TEXT NOT NULL DEFAULT 'pending',
          applied INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`,
      ).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_payments_account ON payments (account_id, created_at)').run();
      await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_legacy ON accounts (legacy_tenant_id) WHERE legacy_tenant_id IS NOT NULL').run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_tenants_account ON tenants (account_id)').run();
      // Migração: cada loja antiga vira "conta + 1 loja" (sem mudar link, senha ou produtos).
      const orphan = await env.DB.prepare('SELECT 1 FROM tenants WHERE account_id IS NULL LIMIT 1').first();
      if (orphan) {
        await env.DB.batch([
          env.DB.prepare(
            `INSERT OR IGNORE INTO accounts (owner_name, whatsapp, password_hash, plan, status, trial_ends_at, paid_until,
                                             created_at, updated_at, last_seen_at, last_login_at, legacy_tenant_id)
             SELECT owner_name, whatsapp, password_hash, 'basic', status, trial_ends_at, paid_until,
                    created_at, updated_at, last_seen_at, last_login_at, id
               FROM tenants WHERE account_id IS NULL`,
          ),
          env.DB.prepare(
            'UPDATE tenants SET account_id = (SELECT a.id FROM accounts a WHERE a.legacy_tenant_id = tenants.id) WHERE account_id IS NULL',
          ),
        ]);
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

const UA_BROWSER = 'Mozilla/5.0 (Linux; Android 13; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36';
const UA_CRAWLERS = [
  'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
  'WhatsApp/2.24.6.77 A',
];

function decodeEntities(v) {
  return String(v || '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}

// Lê título, imagem, URL e preço das etiquetas de prévia (Open Graph) da página.
function readMeta(html) {
  const get = (prop) => {
    const re1 = new RegExp(`<meta[^>]+(?:property|name)=["']${prop}["'][^>]*content=["']([^"']*)`, 'i');
    const re2 = new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]*(?:property|name)=["']${prop}["']`, 'i');
    const m = html.match(re1) || html.match(re2);
    return m ? decodeEntities(m[1]).trim() : '';
  };
  const canonical = (html.match(/<link[^>]+rel=["']canonical["'][^>]*href=["']([^"']+)/i) || [])[1] || '';
  const price = get('product:price:amount') || get('og:price:amount');
  const all = [];
  for (const m of html.matchAll(/<meta\s[^>]{0,600}>/gi)) {
    const tag = m[0];
    const key = (tag.match(/(?:property|name)=["']([^"']+)/i) || [])[1];
    const val = (tag.match(/content=["']([^"']*)/i) || [])[1];
    if (key && val && all.length < 30) all.push(`${key}=${decodeEntities(val).slice(0, 140)}`);
  }
  return {
    all,
    title: get('og:title') || decodeEntities((html.match(/<title>([^<]{3,200})<\/title>/i) || [])[1] || ''),
    image: get('og:image'),
    url: get('og:url') || decodeEntities(canonical),
    price: price && Number(price.replace(',', '.')) > 0 ? Number(price.replace(',', '.')) : null,
  };
}

// Títulos genéricos (página inicial / bloqueio) não servem como nome de produto.
const GENERIC_TITLE = /^(shopee brasil|mercado livre|mercado libre)\b|ofertas incr[ií]veis|melhores pre[çc]os|acesso negado|access denied|just a moment|verify|captcha/i;
const usefulMeta = (meta) => !!(meta && meta.title && meta.title.length > 6 && !GENERIC_TITLE.test(meta.title));

async function saveDebug(env, key, data) {
  try { await setConfig(env, key, JSON.stringify({ at: nowIso(), ...data }).slice(0, 4000)); } catch { /* diagnóstico é opcional */ }
}

// Segue links curtos (s.shopee.com.br/...) até achar o produto. Tenta como navegador e como
// robô de prévia (WhatsApp/Facebook), que costuma receber a página com os dados do produto.
async function resolveShopee(env, rawUrl) {
  const trace = [];
  let fallbackMeta = null;
  for (const ua of [UA_BROWSER, ...UA_CRAWLERS]) {
    let current = rawUrl;
    for (let hop = 0; hop < 7; hop++) {
      const ids = extractShopeeIds(current);
      if (ids) return { ids, meta: fallbackMeta, trace };
      let res;
      try {
        res = await fetch(current, {
          redirect: 'manual',
          headers: { 'User-Agent': ua, Accept: 'text/html,application/xhtml+xml', 'Accept-Language': 'pt-BR,pt;q=0.9' },
        });
      } catch (err) {
        trace.push({ ua: ua.slice(0, 18), url: current.slice(0, 160), error: String(err && err.message).slice(0, 80) });
        break;
      }
      const location = res.headers.get('Location');
      trace.push({ ua: ua.slice(0, 18), url: current.slice(0, 160), status: res.status, location: location ? location.slice(0, 300) : null });
      if (location && res.status >= 300 && res.status < 400) {
        current = new URL(location, current).toString();
        continue;
      }
      if (res.ok) {
        const html = (await res.text()).slice(0, 400_000);
        const meta = readMeta(html);
        const refresh = (html.match(/http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"']+)/i) || [])[1]
          || (html.match(/(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i) || [])[1];
        const found = extractShopeeIds(meta.url) || extractShopeeIds(refresh ? decodeEntities(refresh) : '') || extractShopeeIds(html);
        trace[trace.length - 1].meta = { title: meta.title.slice(0, 80), url: meta.url.slice(0, 160), refresh: refresh ? refresh.slice(0, 160) : null, tags: meta.all.slice(0, 20) };
        if (usefulMeta(meta) && (!fallbackMeta || !fallbackMeta.image)) fallbackMeta = meta;
        if (found) return { ids: found, meta: fallbackMeta, trace };
        if (refresh && hop < 6) {
          current = new URL(decodeEntities(refresh), current).toString();
          continue;
        }
      }
      break;
    }
  }
  return { ids: null, meta: fallbackMeta, trace };
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

function normalizeWords(t) {
  return String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase()
    .replace(/[^a-z0-9 ]+/g, ' ').split(/\s+/).filter((w) => w.length > 2);
}

function titleSimilarity(a, b) {
  const wa = new Set(normalizeWords(a));
  const wb = new Set(normalizeWords(b));
  if (!wa.size || !wb.size) return 0;
  let hit = 0;
  for (const w of wa) if (wb.has(w)) hit++;
  return hit / Math.min(wa.size, wb.size);
}

function originalFromDiscount(price, rate) {
  const r = Number(rate);
  if (!(price > 0) || !(r > 0 && r < 95)) return null;
  return Math.round((price / (1 - r / 100)) * 100) / 100;
}

function shopeeNodeToProduct(node) {
  const priceValue = Number(node.priceMin || node.price);
  const priceFinal = Number.isFinite(priceValue) && priceValue > 0 ? Math.round(priceValue * 100) / 100 : null;
  return {
    original_price: originalFromDiscount(priceFinal, node.priceDiscountRate),
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

async function shopeeSearchByTitle(creds, title) {
  const keyword = normalizeWords(title).slice(0, 10).join(' ');
  if (!keyword) return null;
  const query = `{ productOfferV2(keyword: ${JSON.stringify(keyword)}, page: 1, limit: 10) {
    nodes { itemId shopId productName price priceMin priceMax imageUrl shopName ratingStar sales priceDiscountRate } } }`;
  const data = await shopeeGraphql(creds, query);
  const nodes = ((data.productOfferV2 || {}).nodes) || [];
  let best = null;
  let bestScore = 0;
  for (const n of nodes) {
    const score = titleSimilarity(title, n.productName);
    if (score > bestScore) { best = n; bestScore = score; }
  }
  return best && bestScore >= 0.75 ? { ...shopeeNodeToProduct(best), source: 'title_match' } : null;
}

async function lookupShopee(env, creds, url) {
  const { ids, meta, trace } = await resolveShopee(env, url);
  if (!ids) {
    await saveDebug(env, 'debug_shopee', { input: url, trace });
    // Achou o nome pela prévia: procura o mesmo produto na API pelo nome para trazer preço e foto.
    if (usefulMeta(meta)) {
      try {
        const found = await shopeeSearchByTitle(creds, meta.title);
        if (found) return found;
      } catch (err) {
        console.error('Shopee busca por nome:', err && err.message);
      }
    }
    if (usefulMeta(meta)) {
      // Sem o código do produto, usa a prévia pública da página (nome e foto).
      return { platform: 'shopee', title: meta.title.replace(/\s*\|\s*Shopee.*$/i, '').slice(0, 120), price: meta.price, image_url: /^https:\/\//.test(meta.image) ? meta.image : null, shop_name: null, source: 'preview' };
    }
    throw new HttpError(422, 'Não consegui abrir este link da Shopee. Tente o link completo do produto (abra o link no navegador e copie o endereço).');
  }
  const query = `{ productOfferV2(shopId: ${ids.shopId}, itemId: ${ids.itemId}, page: 1, limit: 1) {
    nodes { itemId shopId productName price priceMin priceMax imageUrl shopName ratingStar sales priceDiscountRate } } }`;
  const data = await shopeeGraphql(creds, query);
  const node = (((data.productOfferV2 || {}).nodes) || [])[0];
  if (!node) {
    if (usefulMeta(meta)) {
      return { platform: 'shopee', title: meta.title.replace(/\s*\|\s*Shopee.*$/i, '').slice(0, 120), price: meta.price, image_url: /^https:\/\//.test(meta.image) ? meta.image : null, shop_name: null, source: 'preview' };
    }
    throw new HttpError(404, 'A Shopee não retornou este produto. Ele pode não participar do programa de afiliados.');
  }
  return shopeeNodeToProduct(node);
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
  if (res.status === 403 && (data.code === 'PA_UNAUTHORIZED_RESULT_FROM_POLICIES' || /policy/i.test(data.message || ''))) {
    throw new HttpError(502, 'O aplicativo do Mercado Livre ainda não tem permissão para ler anúncios.', { code: 'ml_permission' });
  }
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

async function resolveMl(rawUrl) {
  const trace = [];
  let fallbackMeta = null;
  for (const ua of [UA_BROWSER, ...UA_CRAWLERS]) {
    let current = rawUrl;
    for (let hop = 0; hop < 8; hop++) {
      const ids = extractMlIds(current);
      if (ids) return { ids, meta: fallbackMeta, trace };
      let res;
      try {
        res = await fetch(current, {
          redirect: 'manual',
          headers: { 'User-Agent': ua, Accept: 'text/html,application/xhtml+xml', 'Accept-Language': 'pt-BR,pt;q=0.9' },
        });
      } catch (err) {
        trace.push({ ua: ua.slice(0, 18), url: current.slice(0, 200), error: String(err && err.message).slice(0, 80) });
        break;
      }
      const location = res.headers.get('Location');
      trace.push({ ua: ua.slice(0, 18), url: current.slice(0, 200), status: res.status, location: location ? location.slice(0, 400) : null });
      if (location && res.status >= 300 && res.status < 400) {
        current = new URL(location, current).toString();
        continue;
      }
      if (res.ok) {
        const html = (await res.text()).slice(0, 600_000);
        const meta = readMeta(html);
        const refresh = (html.match(/http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"']+)/i) || [])[1]
          || (html.match(/(?:window\.)?location(?:\.href|\.replace)?\s*(?:=|\()\s*["']([^"']+)["']/i) || [])[1];
        const itemJson = html.match(/"(?:item_id|itemId|id)"\s*:\s*"(MLB\d{6,})"/);
        const found = extractMlIds(meta.url) || extractMlIds(refresh ? decodeEntities(refresh) : '')
          || (itemJson ? { itemId: itemJson[1], productId: null } : null);
        trace[trace.length - 1].meta = { title: meta.title.slice(0, 80), url: meta.url.slice(0, 200), refresh: refresh ? refresh.slice(0, 200) : null, tags: meta.all.slice(0, 20) };
        if (usefulMeta(meta) && (!fallbackMeta || !fallbackMeta.image)) fallbackMeta = meta;
        if (found) return { ids: found, meta: fallbackMeta, trace };
        if (refresh && hop < 7) {
          current = new URL(decodeEntities(refresh), current).toString();
          continue;
        }
      }
      break;
    }
  }
  return { ids: null, meta: fallbackMeta, trace };
}

// Prévia pública da página (nome/foto/preço), usada quando a API não libera o anúncio.
async function fetchPreview(url) {
  for (const ua of [...UA_CRAWLERS, UA_BROWSER]) {
    try {
      const res = await fetch(url, { headers: { 'User-Agent': ua, Accept: 'text/html', 'Accept-Language': 'pt-BR,pt;q=0.9' } });
      if (!res.ok) continue;
      const meta = readMeta((await res.text()).slice(0, 600_000));
      if (usefulMeta(meta)) return meta;
    } catch { /* tenta o próximo */ }
  }
  return null;
}

const httpsImage = (u) => (u ? String(u).replace(/^http:\/\//i, 'https://') : null);

async function lookupMercadoLivre(env, token, url) {
  const { ids, meta, trace } = await resolveMl(url);
  if (!ids) {
    await saveDebug(env, 'debug_ml', { input: url, trace });
    if (usefulMeta(meta)) {
      return {
        platform: 'mercadolivre',
        title: meta.title.replace(/\s*[|-]\s*Mercado Livre.*$/i, '').slice(0, 120),
        price: meta.price,
        image_url: /^https:\/\//.test(meta.image) ? meta.image : null,
        shop_name: null,
        source: 'preview',
      };
    }
    throw new HttpError(422, 'Não consegui abrir este link do Mercado Livre. Tente o link completo do produto (abra o link no navegador e copie o endereço).');
  }
  let apiError = null;
  try {
    if (ids.itemId) {
      const item = await mlGet(token, `/items/${ids.itemId}`);
      if (item && item.title) {
        return {
          platform: 'mercadolivre',
          title: String(item.title).slice(0, 120),
          price: Number(item.price) > 0 ? Number(item.price) : null,
          original_price: Number(item.original_price) > Number(item.price) ? Number(item.original_price) : null,
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
          original_price: prod.buy_box_winner && Number(prod.buy_box_winner.original_price) > price ? Number(prod.buy_box_winner.original_price) : null,
          image_url: httpsImage(prod.pictures && prod.pictures[0] && (prod.pictures[0].secure_url || prod.pictures[0].url)),
          shop_name: null,
        };
      }
    }
  } catch (err) {
    apiError = err;
    console.error('Mercado Livre API:', err && err.message);
  }
  // A API não liberou: usa a prévia pública da página do produto.
  let preview = usefulMeta(meta) ? meta : null;
  if (!preview) {
    const pageUrl = ids.itemId ? `https://produto.mercadolivre.com.br/MLB-${ids.itemId.replace(/^MLB/i, '')}` : `https://www.mercadolivre.com.br/p/${ids.productId}`;
    preview = await fetchPreview(pageUrl);
  }
  if (apiError && apiError.extra && apiError.extra.code === 'ml_permission') {
    await saveDebug(env, 'debug_ml', { input: url, ids, error: 'ml_permission', preview: preview ? preview.title : null });
  }
  if (preview) {
    return { platform: 'mercadolivre', title: preview.title.replace(/\s*[|-]\s*Mercado Livre.*$/i, '').slice(0, 120), price: preview.price, image_url: /^https:\/\//.test(preview.image) ? preview.image : null, shop_name: null, source: 'preview' };
  }
  if (apiError) throw apiError;
  if (usefulMeta(meta)) {
    return { platform: 'mercadolivre', title: meta.title.replace(/\s*[|-]\s*Mercado Livre.*$/i, '').slice(0, 120), price: meta.price, image_url: /^https:\/\//.test(meta.image) ? meta.image : null, shop_name: null, source: 'preview' };
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

/* ---------- Buscador de links (Master) ---------- */

// Segue um link de afiliado (meli.la / mercadolivre.com/sec) e guarda os parâmetros matt_* que ele carrega.
async function resolveAffiliateParams(rawUrl) {
  const params = {};
  const collect = (u) => {
    try {
      const url = new URL(u);
      for (const [k, v] of url.searchParams) if (/^matt_/i.test(k) && v) params[k] = v;
      const hash = new URLSearchParams(url.hash.replace(/^#/, ''));
      for (const [k, v] of hash) if (/^matt_/i.test(k) && v) params[k] = v;
    } catch { /* ignora */ }
  };
  let current = rawUrl;
  const trail = [];
  for (let hop = 0; hop < 8; hop++) {
    collect(current);
    trail.push(current.slice(0, 220));
    let res;
    try {
      res = await fetch(current, { redirect: 'manual', headers: { 'User-Agent': UA_BROWSER, Accept: 'text/html' } });
    } catch {
      break;
    }
    const location = res.headers.get('Location');
    if (location && res.status >= 300 && res.status < 400) {
      current = new URL(location, current).toString();
      continue;
    }
    if (res.ok) {
      const html = (await res.text()).slice(0, 400_000);
      const meta = readMeta(html);
      if (meta.url) collect(meta.url);
      for (const m of html.matchAll(/https?:\/\/[^"'\s<>]+matt_[^"'\s<>]+/gi)) collect(decodeEntities(m[0]));
    }
    break;
  }
  return { params, trail };
}

function withAffiliate(url, aff) {
  try {
    const u = new URL(url);
    for (const [k, v] of Object.entries(aff || {})) u.searchParams.set(k, v);
    return u.toString();
  } catch {
    return url;
  }
}

async function handleMlAffiliate(request, env) {
  const body = await readJson(request);
  const link = httpUrl(body.link, 'Link de afiliado', { required: true });
  const { params, trail } = await resolveAffiliateParams(link);
  if (!params.matt_tool) {
    await saveDebug(env, 'debug_ml_affiliate', { input: link, trail, params });
    throw new HttpError(422, 'Não encontrei o código de afiliado neste link. Abra o seu link no navegador, copie o endereço completo da página do produto (com "matt_tool") e cole aqui.');
  }
  await setConfig(env, 'ml_affiliate_params', JSON.stringify(params));
  return json({ params });
}

const SEARCH_SORTS = { relevance: 'relevance', price_asc: 'price_asc', price_desc: 'price_desc', discount: 'relevance' };

function splitTerms(value, max = 30) {
  return String(value || '').split(/[,\n;]+/).map((t) => t.trim()).filter(Boolean).slice(0, max);
}

async function handleMlSearch(request, env) {
  const body = await readJson(request);
  const cfg = await getConfig(env);
  const token = await mlAccessToken(env, cfg);
  if (!token) throw new HttpError(400, 'Conecte o Mercado Livre primeiro (⚙️ → Conectar Mercado Livre).');
  const queries = splitTerms(body.query, 10);
  if (!queries.length) throw new HttpError(400, 'Digite pelo menos um termo de busca.');
  const limit = [5, 10, 15, 30].includes(Number(body.limit)) ? Number(body.limit) : 15;
  const sortKey = SEARCH_SORTS[body.sort] ? body.sort : 'relevance';
  const include = splitTerms(body.include).map((t) => normalizeWords(t).join(' ')).filter(Boolean);
  const exclude = splitTerms(body.exclude).map((t) => normalizeWords(t).join(' ')).filter(Boolean);
  const onlyDiscount = bool01(body.only_discount) === 1;
  const freeOnly = bool01(body.free_shipping) === 1;
  const round = clampInt(body.round, 0, 30, 0);               // "Mostrar outros": avança as páginas
  const skip = new Set((Array.isArray(body.skip_ids) ? body.skip_ids : []).slice(0, 500).map(String));
  const aff = JSON.parse(cfg.ml_affiliate_params || '{}');
  const debug = { at: nowIso(), queries, round, source: null, calls: 0, errors: [], raw: 0, rejected: 0 };

  const accepts = (title) => {
    const norm = ` ${normalizeWords(title).join(' ')} `;
    if (exclude.some((w) => norm.includes(` ${w} `) || (w.length > 4 && norm.includes(w)))) return false;
    if (include.length && !include.some((w) => norm.includes(w))) return false;
    return true;
  };
  const passesFilters = (it) => (!onlyDiscount || it.discount) && (!freeOnly || it.free_shipping);
  const mkItem = (id, title, price, original, image, permalink, free, q) => {
    const p = Number(price) > 0 ? Number(price) : null;
    const o = p && Number(original) > p ? Number(original) : null;
    return {
      id, title: String(title || '').slice(0, 160), price: p, original_price: o,
      discount: o ? Math.round((1 - p / o) * 100) : null,
      image: httpsImage(image), permalink, link: withAffiliate(permalink, aff), free_shipping: !!free, query: q,
    };
  };

  // 1) Busca de anúncios (tem preço, desconto e frete na listagem).
  const found = new Map();
  let searchError = null;
  const exhausted = new Set();
  // O Cloudflare permite ~50 consultas externas por clique: a busca usa no máximo ~40.
  for (let page = round; page < round + 3 && found.size < limit * 2 && debug.calls < 12; page++) {
    for (const q of queries) {
      if (debug.calls >= 12 || found.size >= limit * 2) break;
      if (exhausted.has(q)) continue;
      debug.calls++;
      let data;
      try {
        data = await mlGet(token, `/sites/MLB/search?q=${encodeURIComponent(q)}&limit=50&offset=${page * 50}&sort=${SEARCH_SORTS[sortKey]}${freeOnly ? '&shipping_cost=free' : ''}`);
      } catch (err) {
        searchError = err;
        debug.errors.push(`search: ${err.message}`);
        break;
      }
      const results = (data && data.results) || [];
      debug.raw += results.length;
      for (const r of results) {
        if (!r || !r.id || found.has(r.id) || skip.has(r.id)) continue;
        if (!accepts(r.title)) { debug.rejected++; continue; }
        const it = mkItem(r.id, r.title, r.price, r.original_price,
          r.thumbnail ? String(r.thumbnail).replace(/-I\.(jpg|webp)$/i, '-O.$1') : null,
          r.permalink, r.shipping && r.shipping.free_shipping, q);
        if (passesFilters(it)) found.set(r.id, it);
      }
      if (results.length < 50) exhausted.add(q);
    }
    if (searchError || exhausted.size === queries.length) break;
  }
  debug.source = 'items';

  // 2) Busca de anúncios bloqueada: usa o catálogo e busca preço/frete de cada produto.
  const warnings = [];
  if (!found.size && searchError) {
    debug.source = 'catalog';
    const candidates = new Map();
    let catalogCalls = 0;
    for (const q of queries) {
      if (candidates.size >= limit * 3 || catalogCalls >= 6) break;
      catalogCalls++;
      debug.calls++;
      let data;
      try {
        data = await mlGet(token, `/products/search?status=active&site_id=MLB&q=${encodeURIComponent(q)}&limit=50&offset=${round * 50}`);
      } catch (err) {
        debug.errors.push(`catalog: ${err.message}`);
        await saveDebug(env, 'debug_ml_search', debug);
        throw searchError.extra && searchError.extra.code === 'ml_permission'
          ? new HttpError(502, 'O Mercado Livre não liberou a busca para o seu aplicativo. Confira as permissões no DevCenter e reconecte.', { code: 'ml_permission' })
          : searchError;
      }
      const results = (data && data.results) || [];
      debug.raw += results.length;
      for (const r of results) {
        if (!r || !r.id || candidates.has(r.id) || skip.has(r.id)) continue;
        if (!accepts(r.name)) { debug.rejected++; continue; }
        candidates.set(r.id, { r, q });
      }
    }
    // Detalhes (preço do vendedor da vez, preço antigo, frete) em lotes — no máximo 28 consultas.
    const list = [...candidates.values()].slice(0, Math.min(28, Math.max(limit * 2, 10)));
    const detailed = [];
    debug.details_ok = 0;
    for (let i = 0; i < list.length; i += 7) {
      const batch = list.slice(i, i + 7);
      const details = await Promise.all(batch.map(({ r }) => mlGet(token, `/products/${r.id}`).catch((err) => ({ __error: err.message }))));
      debug.calls += batch.length;
      batch.forEach(({ r, q }, k) => {
        const d = details[k] || {};
        if (d.__error) debug.errors.push(`product: ${d.__error}`.slice(0, 120));
        const w = d.buy_box_winner || {};
        if (Number(w.price) > 0) debug.details_ok++;
        const pics = (d.pictures && d.pictures.length ? d.pictures : r.pictures) || [];
        detailed.push(mkItem(r.id, d.name || r.name, w.price, w.original_price,
          pics[0] && (pics[0].secure_url || pics[0].url), `https://www.mercadolivre.com.br/p/${r.id}`,
          w.shipping && w.shipping.free_shipping, q));
      });
    }
    // Nunca zera o resultado por falta de dados: se não deu para ver preço/frete, mostra sem esse filtro e avisa.
    const withPrice = detailed.filter((it) => it.price);
    let pool = detailed.filter(passesFilters);
    if (!pool.length && (onlyDiscount || freeOnly) && detailed.length) {
      pool = detailed;
      warnings.push(withPrice.length
        ? 'Nenhum produto com desconto/frete grátis nesta leva. Mostrando os encontrados — toque em "Mostrar outros" para ver mais.'
        : 'O Mercado Livre não informou preço e frete destes produtos, então os filtros "desconto" e "frete grátis" não puderam ser aplicados.');
    }
    if (!withPrice.length && detailed.length) {
      warnings.push('Os preços não vieram pela API do Mercado Livre. Os links funcionam normalmente; confira o preço ao abrir.');
    }
    // Com preço primeiro quando a ordem depende de preço/desconto.
    for (const it of pool) found.set(it.id, it);
  }

  let items = [...found.values()];
  if (sortKey === 'discount') items.sort((a, b) => (b.discount || 0) - (a.discount || 0));
  if (sortKey === 'price_asc') items.sort((a, b) => (a.price ?? Infinity) - (b.price ?? Infinity));
  if (sortKey === 'price_desc') items.sort((a, b) => (b.price ?? -1) - (a.price ?? -1));
  items = items.slice(0, limit);
  debug.returned = items.length;
  await saveDebug(env, 'debug_ml_search', debug);
  return json({ items, source: debug.source, affiliate: aff, affiliate_ok: Object.keys(aff).length > 0, calls: debug.calls, round, analyzed: debug.raw, rejected: debug.rejected, warnings });
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

async function lookupQuota(env, tenantId, limitOverride = null) {
  const since = new Date(Date.now() - 3_600_000).toISOString();
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS used, MIN(at) AS oldest FROM lookup_usage WHERE tenant_id = ? AND at > ?',
  ).bind(tenantId, since).first();
  const limit = limitOverride || lookupLimit(env);
  const used = Number(row && row.used) || 0;
  const resetMin = row && row.oldest ? Math.max(1, Math.ceil((Date.parse(row.oldest) + 3_600_000 - Date.now()) / 60_000)) : 60;
  return { limit, used, remaining: Math.max(0, limit - used), reset_minutes: used ? resetMin : null };
}

async function lookupProduct(env, rawUrl, { useCache = true, tenantId = null, limit = null } = {}) {
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
    const quota = await lookupQuota(env, tenantId, limit);
    if (quota.remaining <= 0) {
      throw new HttpError(429, `Você usou as ${quota.limit} buscas automáticas desta hora. Libera de novo em ${quota.reset_minutes} min — enquanto isso, preencha manualmente.`, { code: 'quota', quota });
    }
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
  // A cota só é gasta quando a busca dá certo.
  if (tenantId) {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO lookup_usage (tenant_id, at) VALUES (?, ?)').bind(tenantId, nowIso()),
      env.DB.prepare('DELETE FROM lookup_usage WHERE at < ?').bind(new Date(Date.now() - 2 * 3_600_000).toISOString()),
    ]);
  }
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

// O token identifica a CONTA (que pode ter várias lojas).
async function signToken(env, account) {
  const body = b64u(enc.encode(JSON.stringify({
    aid: account.id,
    pv: passwordVersion(account.password_hash),
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
    if (!payload.exp || payload.exp < Date.now() || !(payload.aid || payload.tid)) return null;
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

/* ------------------------------------------------------------------ */
/* Planos                                                              */
/* ------------------------------------------------------------------ */

const PLANS = {
  basic: { id: 'basic', name: 'Básico', stores: 1, templates: [1], customTemplates: false },
  complete: { id: 'complete', name: 'Completo', stores: 3, templates: [1, 2, 3], customTemplates: true },
};
const planPrice = (env, plan) => (plan === 'complete' ? env.PLAN_PRICE_COMPLETE || '29,90' : env.PLAN_PRICE || '19,90');
const lookupLimitFor = (env, plan) => (plan === 'complete'
  ? clampInt(env.LOOKUP_LIMIT_COMPLETE, 1, 1000, 30)
  : clampInt(env.LOOKUP_LIMIT_PER_HOUR, 1, 1000, 15));
// Durante o teste grátis a conta usa tudo do plano Completo.
const effectivePlan = (acc) => (acc.status === 'trial' ? 'complete' : PLANS[acc.plan] ? acc.plan : 'basic');

function planInfo(env, acc) {
  const id = effectivePlan(acc);
  const p = PLANS[id];
  return {
    id, name: p.name, stores: p.stores, templates: p.templates, custom_templates: p.customTemplates,
    lookups: lookupLimitFor(env, id), price: planPrice(env, id), contracted: PLANS[acc.plan] ? acc.plan : 'basic',
    trial: acc.status === 'trial',
  };
}

function plansCatalog(env) {
  return Object.values(PLANS).map((p) => ({
    id: p.id, name: p.name, stores: p.stores, templates: p.templates.length, custom_templates: p.customTemplates,
    lookups: lookupLimitFor(env, p.id), price: planPrice(env, p.id),
  }));
}

function accountPrivate(env, a) {
  return {
    id: a.id,
    owner_name: a.owner_name,
    whatsapp: a.whatsapp,
    plan: PLANS[a.plan] ? a.plan : 'basic',
    status: a.status,
    trial_ends_at: a.trial_ends_at,
    trial_days_left: a.status === 'trial' ? daysLeft(a.trial_ends_at) : 0,
    paid_until: a.paid_until,
    paid_days_left: a.status === 'active' ? (a.paid_until ? daysLeft(a.paid_until) : null) : 0,
    created_at: a.created_at,
    last_seen_at: a.last_seen_at || null,
    last_login_at: a.last_login_at || null,
    online: !!a.last_seen_at && Date.now() - Date.parse(a.last_seen_at) < ONLINE_WINDOW_MS,
    plan_info: planInfo(env, a),
  };
}

/* ------------------------------------------------------------------ */
/* Sessão do lojista: conta + loja selecionada                         */
/* ------------------------------------------------------------------ */

async function requireAccount(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const payload = await verifyToken(env, token);
  if (!payload) throw new HttpError(401, 'Sessão expirada. Entre novamente.');
  const account = payload.aid
    ? await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(payload.aid).first()
    // Tokens antigos (antes das contas) apontavam para a loja.
    : await env.DB.prepare('SELECT a.* FROM accounts a JOIN tenants t ON t.account_id = a.id WHERE t.id = ?').bind(payload.tid).first();
  if (!account || passwordVersion(account.password_hash) !== payload.pv) {
    throw new HttpError(401, 'Sessão expirada. Entre novamente.');
  }
  return refreshAccount(env, account);
}

// Loja "vestida" com o status da conta (status, teste e vencimento vêm da conta).
function mergeStore(t, a) {
  return {
    ...t,
    account_id: a.id,
    status: a.status,
    trial_ends_at: a.trial_ends_at,
    paid_until: a.paid_until,
    last_seen_at: a.last_seen_at,
    last_login_at: a.last_login_at,
    account: a,
  };
}

// Lojas além do limite do plano (ex.: criou 3 no teste e assinou o Básico) ficam pausadas, sem apagar nada.
async function storeOverLimit(env, account, storeId) {
  const max = PLANS[effectivePlan(account)].stores;
  const { results } = await env.DB.prepare('SELECT id FROM tenants WHERE account_id = ? ORDER BY created_at ASC, id ASC LIMIT ?')
    .bind(account.id, max).all();
  return !(results || []).some((r) => r.id === storeId);
}

async function requireStore(request, env, account) {
  const wanted = String(request.headers.get('X-Store') || new URL(request.url).searchParams.get('store') || '').trim().toLowerCase();
  let t = null;
  if (wanted) t = await env.DB.prepare('SELECT * FROM tenants WHERE id = ? AND account_id = ?').bind(wanted, account.id).first();
  if (!t) t = await env.DB.prepare('SELECT * FROM tenants WHERE account_id = ? ORDER BY created_at ASC LIMIT 1').bind(account.id).first();
  if (!t) throw new HttpError(404, 'Nenhuma loja nesta conta. Crie a sua primeira loja.', { code: 'no_store' });
  const merged = mergeStore(t, account);
  merged.paused = await storeOverLimit(env, account, t.id);
  return merged;
}

async function loadAccountStores(env, accountId) {
  const { results } = await env.DB.prepare(
    `SELECT t.id, t.store_name, t.avatar_url, t.theme_color, t.views, t.created_at,
            (SELECT COUNT(*) FROM products p WHERE p.tenant_id = t.id) AS product_count
       FROM tenants t WHERE t.account_id = ? ORDER BY t.created_at ASC, t.id ASC`,
  ).bind(accountId).all();
  return results || [];
}

async function loadAccountStoresFor(env, account) {
  const max = PLANS[effectivePlan(account)].stores;
  return (await loadAccountStores(env, account.id)).map((r, i) => ({
    ...r, views: Number(r.views || 0), product_count: Number(r.product_count || 0), paused: i >= max,
  }));
}

// Loja pública com o status da conta dona.
async function loadPublicStore(env, id) {
  const t = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(id).first();
  if (!t) return null;
  let a = t.account_id ? await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(t.account_id).first() : null;
  if (!a) return t; // banco ainda não migrado: usa os campos da própria loja
  a = await refreshAccount(env, a);
  const merged = mergeStore(t, a);
  // Loja pausada pelo limite do plano aparece como indisponível.
  if (merged.status !== 'expired' && await storeOverLimit(env, a, t.id)) merged.status = 'expired';
  return merged;
}

function assertCanEdit(tenant) {
  if (tenant.paused) {
    throw new HttpError(403, 'Esta loja está pausada porque o seu plano permite menos lojas. Mude para o Completo para reativá-la.', { code: 'store_paused' });
  }
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

async function refreshAccount(env, account) {
  if (account && isLapsed(account)) {
    const ts = nowIso();
    await env.DB.prepare(
      "UPDATE accounts SET status = 'expired', updated_at = ? WHERE id = ? AND status IN ('trial', 'active')",
    ).bind(ts, account.id).run();
    account.status = 'expired';
    account.updated_at = ts;
  }
  return account;
}

async function expireLapsedAccounts(env) {
  const ts = nowIso();
  await env.DB.prepare(
    `UPDATE accounts SET status = 'expired', updated_at = ?
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
    cover_url: t.cover_url || null,
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

const DEFAULT_SETTINGS = {
  show_prices: 1, show_stock_warning: 1, view_mode: 'grid', show_banner: 1, share_message: '', offer_template: 1,
  theme_mode: 'light', card_tone: 'white', offer_templates: '', show_whatsapp: 1, store_mode: 'mixed',
};
// Tipo da loja: só afiliados, só catálogo da região (com carrinho) ou os dois.
const STORE_MODES = ['affiliate', 'local', 'mixed'];
const storeMode = (v) => (STORE_MODES.includes(v) ? v : 'mixed');

async function loadSettings(env, tenantId) {
  const row = await env.DB.prepare(
    `SELECT show_prices, show_stock_warning, view_mode, show_banner, share_message, offer_template,
            theme_mode, card_tone, offer_templates, show_whatsapp, store_mode FROM tenant_settings WHERE tenant_id = ?`,
  ).bind(tenantId).first();
  return row ? { ...DEFAULT_SETTINGS, ...row } : { ...DEFAULT_SETTINGS };
}

async function loadProducts(env, tenantId, { onlyVisible = false } = {}) {
  const { results } = await env.DB.prepare(
    `SELECT id, title, description, price, image_url, affiliate_link, platform,
            is_physical, delivery_cities, sort_order, is_visible, show_price, original_price, category, created_at, updated_at
       FROM products WHERE tenant_id = ? ${onlyVisible ? 'AND is_visible = 1' : ''}
      ORDER BY sort_order ASC, id DESC`,
  ).bind(tenantId).all();
  return results || [];
}

async function touchPresence(env, accountId, { login = false } = {}) {
  const ts = nowIso();
  await env.DB.prepare(
    login
      ? 'UPDATE accounts SET last_seen_at = ?, last_login_at = ? WHERE id = ?'
      : 'UPDATE accounts SET last_seen_at = ? WHERE id = ?',
  ).bind(...(login ? [ts, ts, accountId] : [ts, accountId])).run();
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
    plan_price_complete: env.PLAN_PRICE_COMPLETE || '29,90',
    plans: plansCatalog(env),
    payments: mpConfigured(env),
    support_whatsapp: String(cfg.support_whatsapp || env.SUPPORT_WHATSAPP || '').replace(/\D/g, ''),
    video: videoEmbed(cfg.landing_video_url),
    lookup: { shopee: !!(await shopeeCredentials(env, cfg)), mercadolivre: mlConfigured(env) && !!cfg.ml_tokens },
    uploads: !!env.IMAGES,
    public_base_url: publicBase(request, env),
  });
}

// Foto guardada no banco (data URL) vira um link próprio: a vitrine carrega os textos primeiro
// e cada foto só é baixada quando aparece na tela (e fica no cache do navegador).
function photoLink(base, kind, id, dataUrl, version) {
  if (!dataUrl || !String(dataUrl).startsWith('data:')) return dataUrl;
  const v = encodeURIComponent(String(version || '').replace(/\D/g, '').slice(-12) || '1');
  return `${base}/api/photo/${kind}/${encodeURIComponent(id)}?v=${v}`;
}

async function handlePhoto(env, kind, rawId) {
  let row = null;
  if (kind === 'p' && /^\d+$/.test(rawId)) {
    row = await env.DB.prepare('SELECT image_url AS img FROM products WHERE id = ? AND is_visible = 1').bind(Number(rawId)).first();
  } else if (kind === 'c' && SLUG_RE.test(rawId)) {
    row = await env.DB.prepare('SELECT cover_url AS img FROM tenants WHERE id = ?').bind(rawId).first();
  } else if (kind === 's' && SLUG_RE.test(rawId)) {
    row = await env.DB.prepare('SELECT avatar_url AS img FROM tenants WHERE id = ?').bind(rawId).first();
  }
  const m = row && String(row.img || '').match(/^data:(image\/(?:png|jpe?g|webp));base64,(.+)$/);
  if (!m) throw new HttpError(404, 'Imagem não encontrada.');
  return new Response(unb64u(m[2].replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')), {
    headers: {
      'Content-Type': m[1],
      'Cache-Control': 'public, max-age=31536000, immutable', // o ?v= muda quando a foto muda
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

async function handleStore(request, env, rawId) {
  const id = String(rawId || '').toLowerCase();
  if (!SLUG_RE.test(id)) throw new HttpError(404, 'Vitrine não encontrada.');
  const tenant = await loadPublicStore(env, id);
  if (!tenant) throw new HttpError(404, 'Vitrine não encontrada.');

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
  delete settings.offer_template;
  delete settings.offer_templates;

  // Preço oculto (geral ou do produto): o valor nem sai do servidor.
  const base = publicBase(request, env);
  const visibleProducts = products.map((p) => {
    const item = { ...p, image_url: photoLink(base, 'p', p.id, p.image_url, p.updated_at) };
    return settings.show_prices && Number(p.show_price) !== 0 ? item : { ...item, price: null, original_price: null };
  });
  const store = tenantPublic(tenant);
  store.avatar_url = photoLink(base, 's', tenant.id, tenant.avatar_url, tenant.updated_at);
  store.cover_url = photoLink(base, 'c', tenant.id, tenant.cover_url, tenant.updated_at);

  return json({ store, settings, products: visibleProducts });
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

// Entrada do lojista: pelo WhatsApp da conta (ou pelo endereço de uma das lojas) + senha.
async function handleLogin(request, env) {
  const body = await readJson(request);
  const raw = String(body.login ?? body.store_id ?? '').trim();
  const pw = String(body.password || '');
  const ip = clientIp(request);
  await checkLocked(env, [`ip:${ip}`]);

  let account = null;
  if (/[a-z]/i.test(raw)) {
    const id = raw.toLowerCase().replace(/^.*\/s\//, '').replace(/[^a-z0-9-]/g, '');
    if (SLUG_RE.test(id)) {
      account = await env.DB.prepare('SELECT a.* FROM accounts a JOIN tenants t ON t.account_id = a.id WHERE t.id = ?').bind(id).first();
    }
  } else {
    let phone = '';
    try { phone = whatsapp(raw); } catch { phone = ''; }
    if (phone) {
      const { results } = await env.DB.prepare('SELECT * FROM accounts WHERE whatsapp = ? ORDER BY created_at LIMIT 2').bind(phone).all();
      if (results && results.length > 1) {
        throw new HttpError(409, 'Há mais de uma conta com este WhatsApp. Entre com o endereço de uma das suas lojas (ex.: loja-do-joao).', { code: 'phone_multiple' });
      }
      account = results && results[0] ? results[0] : null;
    }
  }

  const keys = account ? [`a:${account.id}:${ip}`, `a:${account.id}`] : [];
  if (keys.length) await checkLocked(env, keys);
  const ok = await verifyPassword(pw, account ? account.password_hash : DUMMY_HASH);
  if (!account || !ok) {
    if (account) {
      await registerFail(env, keys[0], { max: 5, windowMin: 15, lockMin: 15 });
      await registerFail(env, keys[1], { max: 20, windowMin: 60, lockMin: 30 });
    } else {
      await registerFail(env, `ip:${ip}`, { max: 20, windowMin: 15, lockMin: 15 });
    }
    throw new HttpError(401, 'WhatsApp ou senha incorretos.');
  }
  await clearFails(env, keys);
  await refreshAccount(env, account);
  account.last_seen_at = account.last_login_at = await touchPresence(env, account.id, { login: true });
  return json({
    token: await signToken(env, account),
    account: accountPrivate(env, account),
    stores: await loadAccountStoresFor(env, account),
  });
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

// Cadastro aberto: cria a conta (7 dias grátis com tudo do plano Completo) + a primeira loja.
async function handleRegister(request, env) {
  const body = await readJson(request);
  if (String(body.website || '').trim()) throw new HttpError(400, 'Não foi possível concluir o cadastro.'); // campo-isca anti-robô
  const { account, store } = await createAccountWithStore(env, body);
  account.last_seen_at = account.last_login_at = await touchPresence(env, account.id, { login: true });
  return json({
    token: await signToken(env, account),
    account: accountPrivate(env, account),
    stores: await loadAccountStoresFor(env, account),
    store_id: store.id,
    store_url: `${publicBase(request, env)}/s/${store.id}`,
  }, 201);
}

/* ------------------------------------------------------------------ */
/* Handlers do lojista                                                 */
/* ------------------------------------------------------------------ */

async function handleLookup(request, env, tenant) {
  assertCanEdit(tenant);
  const body = await readJson(request);
  const quotaKey = `acc:${tenant.account_id}`;
  const limit = lookupLimitFor(env, effectivePlan(tenant.account));
  const product = await lookupProduct(env, body.url, { tenantId: quotaKey, limit });
  return json({ product, quota: await lookupQuota(env, quotaKey, limit) });
}

async function handlePing(env, account) {
  await touchPresence(env, account.id);
  return json({ ok: true, status: account.status });
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
  await touchPresence(env, tenant.account_id).catch(() => {});
  const plan = effectivePlan(tenant.account);
  const [settings, products, stores] = await Promise.all([
    loadSettings(env, tenant.id), loadProducts(env, tenant.id), loadAccountStoresFor(env, tenant.account),
  ]);
  return json({
    tenant: { ...tenantPrivate(tenant), paused: !!tenant.paused },
    account: accountPrivate(env, tenant.account),
    stores,
    settings,
    products,
    store_url: `${publicBase(request, env)}/s/${tenant.id}`,
    lookup_quota: await lookupQuota(env, `acc:${tenant.account_id}`, lookupLimitFor(env, plan)),
  });
}

// Lista de lojas da conta (tela "Minhas lojas").
async function handleStores(request, env, account) {
  await touchPresence(env, account.id).catch(() => {});
  const base = publicBase(request, env);
  const stores = (await loadAccountStoresFor(env, account)).map((st) => ({ ...st, store_url: `${base}/s/${st.id}` }));
  return json({ account: accountPrivate(env, account), stores, plans: plansCatalog(env) });
}

async function handleCreateStore(request, env, account) {
  assertCanEdit(account);
  const max = PLANS[effectivePlan(account)].stores;
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM tenants WHERE account_id = ?').bind(account.id).first('n');
  if (Number(count) >= max) {
    throw new HttpError(403, max === 1
      ? 'Seu plano Básico permite 1 loja. Mude para o plano Completo para ter até 3 lojas.'
      : `Seu plano permite até ${max} lojas.`, { code: 'store_limit' });
  }
  const body = await readJson(request);
  const store = await createStore(env, account, { ...body, whatsapp: body.whatsapp || account.whatsapp, owner_name: body.owner_name || account.owner_name });
  return json({ store: { ...store, store_url: `${publicBase(request, env)}/s/${store.id}` } }, 201);
}

async function handleDeleteStore(env, account, rawId) {
  const id = String(rawId || '').toLowerCase();
  const t = await env.DB.prepare('SELECT id FROM tenants WHERE id = ? AND account_id = ?').bind(id, account.id).first();
  if (!t) throw new HttpError(404, 'Loja não encontrada.');
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM tenants WHERE account_id = ?').bind(account.id).first('n');
  if (Number(count) <= 1) throw new HttpError(400, 'Esta é a sua única loja e não pode ser excluída.');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM products WHERE tenant_id = ?').bind(id),
    env.DB.prepare('DELETE FROM tenant_settings WHERE tenant_id = ?').bind(id),
    env.DB.prepare('DELETE FROM tenants WHERE id = ?').bind(id),
  ]);
  await deleteAllTenantImages(env, id);
  return json({ ok: true });
}

async function handleProfile(request, env, tenant) {
  assertCanEdit(tenant);
  const body = await readJson(request);
  const data = {
    store_name: text(body.store_name, 80, 'Nome da loja', { required: true }),
    owner_name: text(body.owner_name, 80, 'Seu nome'),
    whatsapp: whatsapp(body.whatsapp, { required: true }),
    avatar_url: httpUrl(body.avatar_url, 'Foto/logo', { allowData: true }),
    cover_url: body.cover_url === undefined ? tenant.cover_url || null : httpUrl(body.cover_url, 'Foto de capa', { allowData: true }),
    theme_color: color(body.theme_color, tenant.theme_color),
  };
  const ts = nowIso();
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE tenants SET store_name = ?, whatsapp = ?, avatar_url = ?, cover_url = ?, theme_color = ?, updated_at = ?
       WHERE id = ?`,
    ).bind(data.store_name, data.whatsapp, data.avatar_url, data.cover_url, data.theme_color, ts, tenant.id),
    // "Seu nome" é da conta: vale para todas as lojas.
    env.DB.prepare('UPDATE tenants SET owner_name = ? WHERE account_id = ?').bind(data.owner_name, tenant.account_id),
    env.DB.prepare('UPDATE accounts SET owner_name = ?, updated_at = ? WHERE id = ?').bind(data.owner_name, ts, tenant.account_id),
  ]);
  if (tenant.avatar_url && tenant.avatar_url !== data.avatar_url) await deleteImage(env, tenant.avatar_url, tenant.id);
  if (tenant.cover_url && tenant.cover_url !== data.cover_url) await deleteImage(env, tenant.cover_url, tenant.id);
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
    offer_template: clampInt(pick('offer_template'), 1, 3, 1),
    theme_mode: pick('theme_mode') === 'dark' ? 'dark' : 'light',
    card_tone: pick('card_tone') === 'tinted' ? 'tinted' : 'white',
    offer_templates: current.offer_templates || '',
    show_whatsapp: bool01(pick('show_whatsapp')),
    store_mode: storeMode(pick('store_mode')),
  };
  // Recursos do plano: modelos 2 e 3 e edição dos modelos são do plano Completo (e do teste grátis).
  const plan = PLANS[effectivePlan(tenant.account)];
  if (!plan.templates.includes(settings.offer_template)) settings.offer_template = 1;
  if (body.offer_templates !== undefined) {
    if (!plan.customTemplates) throw new HttpError(403, 'Editar os modelos de mensagem é um recurso do plano Completo.', { code: 'plan_feature' });
    const tpl = body.offer_templates && typeof body.offer_templates === 'object' ? body.offer_templates : {};
    const clean = {};
    for (const k of ['1', '2', '3']) {
      if (typeof tpl[k] === 'string' && tpl[k].trim()) clean[k] = text(tpl[k], 1200, `Modelo ${k}`);
    }
    settings.offer_templates = Object.keys(clean).length ? JSON.stringify(clean) : '';
  }
  await env.DB.prepare(
    `INSERT INTO tenant_settings (tenant_id, show_prices, show_stock_warning, view_mode, show_banner, share_message,
                                  offer_template, theme_mode, card_tone, offer_templates, show_whatsapp, store_mode)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (tenant_id) DO UPDATE SET
       show_prices = excluded.show_prices,
       show_stock_warning = excluded.show_stock_warning,
       view_mode = excluded.view_mode,
       show_banner = excluded.show_banner,
       share_message = excluded.share_message,
       offer_template = excluded.offer_template,
       theme_mode = excluded.theme_mode,
       card_tone = excluded.card_tone,
       offer_templates = excluded.offer_templates,
       show_whatsapp = excluded.show_whatsapp,
       store_mode = excluded.store_mode`,
  ).bind(tenant.id, settings.show_prices, settings.show_stock_warning, settings.view_mode, settings.show_banner, settings.share_message,
    settings.offer_template, settings.theme_mode, settings.card_tone, settings.offer_templates, settings.show_whatsapp, settings.store_mode).run();
  return json({ settings });
}

async function handlePassword(request, env, tenant) {
  const body = await readJson(request);
  const account = tenant;
  if (!(await verifyPassword(String(body.current_password || ''), account.password_hash))) {
    throw new HttpError(400, 'A senha atual está incorreta.');
  }
  const hash = await hashPassword(password(body.new_password, 'Nova senha'));
  const ts = nowIso();
  await env.DB.batch([
    env.DB.prepare('UPDATE accounts SET password_hash = ?, updated_at = ? WHERE id = ?').bind(hash, ts, account.id),
    env.DB.prepare('UPDATE tenants SET password_hash = ?, updated_at = ? WHERE account_id = ?').bind(hash, ts, account.id),
  ]);
  return json({ ok: true, token: await signToken(env, { ...account, password_hash: hash }) });
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
                           is_physical, delivery_cities, sort_order, show_price, original_price, category, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     RETURNING *`,
  ).bind(
    tenant.id, p.title, p.description, p.price, p.image_url, p.affiliate_link, p.platform,
    p.is_physical, p.delivery_cities, p.sort_order, p.show_price, p.original_price, p.category, ts, ts,
  ).first();
  return json({ product: row }, 201);
}

async function handleUpdateProduct(request, env, tenant, rawId) {
  assertCanEdit(tenant);
  const current = await getOwnedProduct(env, tenant, rawId);
  const p = productInput(await readJson(request));
  const row = await env.DB.prepare(
    `UPDATE products SET title = ?, description = ?, price = ?, image_url = ?, affiliate_link = ?, platform = ?,
                         is_physical = ?, delivery_cities = ?, sort_order = ?, show_price = ?, original_price = ?, category = ?, updated_at = ?
     WHERE id = ? AND tenant_id = ?
     RETURNING *`,
  ).bind(
    p.title, p.description, p.price, p.image_url, p.affiliate_link, p.platform,
    p.is_physical, p.delivery_cities, p.sort_order, p.show_price, p.original_price, p.category, nowIso(), current.id, tenant.id,
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

// Cria uma loja dentro de uma conta (o status/plano vem da conta).
async function createStore(env, account, body) {
  const storeName = text(body.store_name, 80, 'Nome da loja', { required: true });
  const id = storeSlug(body.id ? slugify(body.id) : slugify(storeName));
  const data = {
    id,
    store_name: storeName,
    owner_name: text(body.owner_name, 80, 'Seu nome'),
    whatsapp: whatsapp(body.whatsapp, { required: true }),
    avatar_url: httpUrl(body.avatar_url, 'Foto/logo'),
    theme_color: color(body.theme_color),
  };
  const exists = await env.DB.prepare('SELECT 1 FROM tenants WHERE id = ?').bind(id).first();
  if (exists) throw new HttpError(409, `O endereço "${id}" já está em uso. Escolha outro.`, { code: 'slug_taken' });
  const mode = storeMode(body.store_mode);
  const ts = nowIso();
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO tenants (id, account_id, store_name, owner_name, whatsapp, avatar_url, theme_color, password_hash,
                              status, trial_ends_at, paid_until, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        data.id, account.id, data.store_name, data.owner_name, data.whatsapp, data.avatar_url, data.theme_color,
        account.password_hash, account.status, account.trial_ends_at, account.paid_until || null, ts, ts,
      ),
      // Só afiliados: começa sem o botão de WhatsApp (dá para ligar depois).
      env.DB.prepare(
        'INSERT INTO tenant_settings (tenant_id, show_prices, show_stock_warning, view_mode, store_mode, show_whatsapp) VALUES (?, 1, 1, ?, ?, ?)',
      ).bind(data.id, 'grid', mode, mode === 'affiliate' ? 0 : 1),
    ]);
  } catch (err) {
    if (/UNIQUE|PRIMARY/i.test(String(err && err.message))) {
      throw new HttpError(409, `O endereço "${id}" já está em uso. Escolha outro.`, { code: 'slug_taken' });
    }
    throw err;
  }
  return { ...data, store_mode: mode, views: 0, product_count: 0, created_at: ts };
}

async function createAccountWithStore(env, body, { plan = 'basic' } = {}) {
  const phone = whatsapp(body.whatsapp, { required: true });
  const ownerName = text(body.owner_name, 80, 'Seu nome');
  const hash = await hashPassword(password(body.password));
  // Valida a loja antes de criar a conta (evita conta sem loja).
  const storeName = text(body.store_name, 80, 'Nome da loja', { required: true });
  const slug = storeSlug(body.id ? slugify(body.id) : slugify(storeName));
  if (await env.DB.prepare('SELECT 1 FROM tenants WHERE id = ?').bind(slug).first()) {
    throw new HttpError(409, `O endereço "${slug}" já está em uso. Escolha outro.`, { code: 'slug_taken' });
  }
  await assertPhoneFree(env, phone);
  const createdMs = Date.now();
  const ts = new Date(createdMs).toISOString();
  const trialEndsAt = addDays(createdMs, trialDays(env)); // 7 dias grátis (com tudo do Completo)
  const res = await env.DB.prepare(
    `INSERT INTO accounts (owner_name, whatsapp, password_hash, plan, status, trial_ends_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'trial', ?, ?, ?)`,
  ).bind(ownerName, phone, hash, PLANS[plan] ? plan : 'basic', trialEndsAt, ts, ts).run();
  const accountId = res.meta && res.meta.last_row_id;
  const account = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(accountId).first();
  try {
    const store = await createStore(env, account, { ...body, id: slug, store_name: storeName, whatsapp: phone, owner_name: ownerName });
    return { account, store };
  } catch (err) {
    await env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(accountId).run();
    throw err;
  }
}

/* ------------------------------------------------------------------ */
/* Master: contas                                                      */
/* ------------------------------------------------------------------ */

async function adminAccountView(env, base, a, storesByAccount) {
  const stores = (storesByAccount.get(a.id) || []).map((t) => ({
    id: t.id, store_name: t.store_name, avatar_url: t.avatar_url, theme_color: t.theme_color,
    views: Number(t.views || 0), product_count: Number(t.product_count || 0), store_url: `${base}/s/${t.id}`,
  }));
  const first = stores[0] || {};
  return {
    ...accountPrivate(env, a),
    // Campos da 1ª loja para manter o painel simples
    store_name: first.store_name || '(sem loja)',
    avatar_url: first.avatar_url || '',
    theme_color: first.theme_color || '#16a6e0',
    store_url: first.store_url || '',
    stores,
    store_count: stores.length,
    product_count: stores.reduce((n, t) => n + t.product_count, 0),
    views: stores.reduce((n, t) => n + t.views, 0),
  };
}

async function loadAdminAccounts(env, base, onlyId = null) {
  const accs = onlyId
    ? (await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(onlyId).all()).results || []
    : (await env.DB.prepare('SELECT * FROM accounts ORDER BY created_at DESC').all()).results || [];
  const { results: stores } = await env.DB.prepare(
    `SELECT t.id, t.account_id, t.store_name, t.avatar_url, t.theme_color, t.views, t.created_at,
            (SELECT COUNT(*) FROM products p WHERE p.tenant_id = t.id) AS product_count
       FROM tenants t ${onlyId ? 'WHERE t.account_id = ?' : ''} ORDER BY t.created_at ASC`,
  ).bind(...(onlyId ? [onlyId] : [])).all();
  const map = new Map();
  for (const t of stores || []) {
    if (!map.has(t.account_id)) map.set(t.account_id, []);
    map.get(t.account_id).push(t);
  }
  return Promise.all(accs.map((a) => adminAccountView(env, base, a, map)));
}

async function handleAdminList(request, env) {
  await expireLapsedAccounts(env);
  const accounts = await loadAdminAccounts(env, publicBase(request, env));
  const dayAgo = Date.now() - DAY_MS;
  const toNum = (v) => Number(String(v).replace(/\./g, '').replace(',', '.')) || 0;
  const active = accounts.filter((a) => a.status === 'active');
  const stats = {
    total: accounts.length,
    trial: accounts.filter((a) => a.status === 'trial').length,
    active: active.length,
    expired: accounts.filter((a) => a.status === 'expired').length,
    online: accounts.filter((a) => a.online).length,
    active_today: accounts.filter((a) => a.last_seen_at && Date.parse(a.last_seen_at) >= dayAgo).length,
    with_products: accounts.filter((a) => a.product_count > 0).length,
    products: accounts.reduce((sum, a) => sum + a.product_count, 0),
    views: accounts.reduce((sum, a) => sum + a.views, 0),
    stores: accounts.reduce((sum, a) => sum + a.store_count, 0),
    new_7d: accounts.filter((a) => Date.parse(a.created_at) >= Date.now() - 7 * DAY_MS).length,
    active_basic: active.filter((a) => a.plan === 'basic').length,
    active_complete: active.filter((a) => a.plan === 'complete').length,
  };
  stats.mrr = Math.round((stats.active_basic * toNum(planPrice(env, 'basic')) + stats.active_complete * toNum(planPrice(env, 'complete'))) * 100) / 100;
  return json({
    accounts, tenants: accounts, stats, plans: plansCatalog(env),
    plan_price: planPrice(env, 'basic'), plan_price_complete: planPrice(env, 'complete'),
    trial_days: trialDays(env), server_time: nowIso(),
  });
}

async function handleAdminCreate(request, env) {
  const body = await readJson(request);
  const { account } = await createAccountWithStore(env, body, { plan: body.plan });
  const [view] = await loadAdminAccounts(env, publicBase(request, env), account.id);
  return json({ account: view, tenant: view }, 201);
}

// Aceita o id numérico da conta ou o endereço de uma das lojas.
async function findAccount(env, rawId) {
  const id = String(rawId || '').trim().toLowerCase();
  if (/^\d+$/.test(id)) {
    const a = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(Number(id)).first();
    if (a) return a;
  }
  return env.DB.prepare('SELECT a.* FROM accounts a JOIN tenants t ON t.account_id = a.id WHERE t.id = ?').bind(id).first();
}

async function handleAdminPatch(request, env, rawId) {
  const acc = await findAccount(env, rawId);
  if (!acc) throw new HttpError(404, 'Conta não encontrada.');
  const id = acc.id;
  const body = await readJson(request);
  const ts = nowIso();
  const now = Date.now();
  const planOf = (v) => (PLANS[v] ? v : null);

  switch (body.action) {
    case 'activate': {
      // Soma os dias ao que ainda resta do plano pago (renovação não perde dias).
      const days = clampInt(body.days, 1, 3650, 30);
      const plan = planOf(body.plan) || acc.plan || 'basic';
      const current = acc.status === 'active' && acc.paid_until ? Date.parse(acc.paid_until) : 0;
      const paidUntil = addDays(Math.max(now, current), days);
      await env.DB.prepare("UPDATE accounts SET status = 'active', plan = ?, paid_until = ?, updated_at = ? WHERE id = ?")
        .bind(plan, paidUntil, ts, id).run();
      break;
    }
    case 'set_plan': {
      const plan = planOf(body.plan);
      if (!plan) throw new HttpError(400, 'Plano inválido.');
      await env.DB.prepare('UPDATE accounts SET plan = ?, updated_at = ? WHERE id = ?').bind(plan, ts, id).run();
      break;
    }
    case 'extend_trial': {
      const days = clampInt(body.days, 1, 365, 7);
      const current = Date.parse(acc.trial_ends_at) || 0;
      const trialEndsAt = addDays(Math.max(now, current), days);
      await env.DB.prepare("UPDATE accounts SET status = 'trial', trial_ends_at = ?, updated_at = ? WHERE id = ?")
        .bind(trialEndsAt, ts, id).run();
      break;
    }
    case 'expire':
      await env.DB.prepare("UPDATE accounts SET status = 'expired', updated_at = ? WHERE id = ?").bind(ts, id).run();
      break;
    case 'reset_password': {
      const hash = await hashPassword(password(body.password, 'Nova senha'));
      await env.DB.batch([
        env.DB.prepare('UPDATE accounts SET password_hash = ?, updated_at = ? WHERE id = ?').bind(hash, ts, id),
        env.DB.prepare('UPDATE tenants SET password_hash = ? WHERE account_id = ?').bind(hash, id),
        env.DB.prepare('DELETE FROM login_attempts WHERE key = ? OR key LIKE ?').bind(`a:${id}`, `a:${id}:%`),
      ]);
      break;
    }
    case 'update': {
      const ownerName = text(body.owner_name ?? acc.owner_name, 80, 'Nome do responsável');
      const phone = whatsapp(body.whatsapp ?? acc.whatsapp, { required: true });
      await assertPhoneFree(env, phone, id);
      await env.DB.prepare('UPDATE accounts SET owner_name = ?, whatsapp = ?, updated_at = ? WHERE id = ?')
        .bind(ownerName, phone, ts, id).run();
      if (body.store_name !== undefined && body.store_id) {
        const storeName = text(body.store_name, 80, 'Nome da loja', { required: true });
        await env.DB.prepare('UPDATE tenants SET store_name = ?, updated_at = ? WHERE id = ? AND account_id = ?')
          .bind(storeName, ts, String(body.store_id).toLowerCase(), id).run();
      }
      break;
    }
    default:
      throw new HttpError(400, 'Ação inválida.');
  }
  const [view] = await loadAdminAccounts(env, publicBase(request, env), id);
  return json({ account: view, tenant: view });
}

async function handleAdminDelete(env, rawId) {
  const acc = await findAccount(env, rawId);
  if (!acc) throw new HttpError(404, 'Conta não encontrada.');
  const { results } = await env.DB.prepare('SELECT id FROM tenants WHERE account_id = ?').bind(acc.id).all();
  const ids = (results || []).map((r) => r.id);
  const stmts = [];
  for (const sid of ids) {
    stmts.push(env.DB.prepare('DELETE FROM products WHERE tenant_id = ?').bind(sid));
    stmts.push(env.DB.prepare('DELETE FROM tenant_settings WHERE tenant_id = ?').bind(sid));
  }
  stmts.push(env.DB.prepare('DELETE FROM tenants WHERE account_id = ?').bind(acc.id));
  stmts.push(env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(acc.id));
  await env.DB.batch(stmts);
  for (const sid of ids) await deleteAllTenantImages(env, sid);
  return json({ ok: true });
}


/* ------------------------------------------------------------------ */
/* Pagamentos: Mercado Pago (Pix no painel ou cartão no checkout)     */
/* ------------------------------------------------------------------ */
// Segredos no Cloudflare: MP_ACCESS_TOKEN (obrigatório) e MP_WEBHOOK_SECRET (opcional, valida a assinatura do aviso).

const MP_API = 'https://api.mercadopago.com';
const mpConfigured = (env) => !!env.MP_ACCESS_TOKEN;
const priceNumber = (v) => Math.round((Number(String(v).replace(/\./g, '').replace(',', '.')) || 0) * 100) / 100;

async function mpFetch(env, path, { method = 'GET', body, idem } = {}) {
  const headers = { Authorization: `Bearer ${env.MP_ACCESS_TOKEN}`, Accept: 'application/json' };
  if (body) headers['Content-Type'] = 'application/json';
  if (idem) headers['X-Idempotency-Key'] = idem;
  let res;
  try {
    res = await fetch(MP_API + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  } catch {
    throw new HttpError(502, 'Não foi possível falar com o Mercado Pago agora. Tente de novo em instantes.');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    await saveDebug(env, 'debug_mp', { path, status: res.status, data }).catch(() => {});
    const msg = (data && (data.message || (data.cause && data.cause[0] && data.cause[0].description))) || '';
    throw new HttpError(502, `O Mercado Pago recusou a cobrança${msg ? `: ${msg}` : ''}.`, { code: 'mp_error' });
  }
  return data;
}

// Aplica o pagamento aprovado na conta (uma vez só): plano escolhido + dias somados ao que resta.
async function applyPayment(env, pay) {
  const claim = await env.DB.prepare(
    "UPDATE payments SET applied = 1, status = 'approved', updated_at = ? WHERE id = ? AND applied = 0",
  ).bind(nowIso(), pay.id).run();
  if (!claim.meta || !claim.meta.changes) return false; // já aplicado
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(pay.account_id).first();
  if (!acc) return false;
  const now = Date.now();
  const current = acc.status === 'active' && acc.paid_until ? Date.parse(acc.paid_until) : 0;
  const paidUntil = addDays(Math.max(now, current), pay.days || 30);
  await env.DB.prepare("UPDATE accounts SET status = 'active', plan = ?, paid_until = ?, updated_at = ? WHERE id = ?")
    .bind(PLANS[pay.plan] ? pay.plan : 'basic', paidUntil, nowIso(), acc.id).run();
  return true;
}

// Confere no Mercado Pago (fonte da verdade) e atualiza o pagamento local.
async function syncPayment(env, pay, mpPayment = null) {
  let mp = mpPayment;
  if (!mp) {
    if (pay.mp_id && pay.method === 'pix') {
      mp = await mpFetch(env, `/v1/payments/${encodeURIComponent(pay.mp_id)}`);
    } else {
      // Cartão (checkout): procura o pagamento pela referência.
      const found = await mpFetch(env, `/v1/payments/search?external_reference=${encodeURIComponent(pay.ref)}&sort=date_created&criteria=desc`);
      mp = (found.results || []).find((r) => r.status === 'approved') || (found.results || [])[0] || null;
    }
  }
  if (!mp || mp.external_reference !== pay.ref) return pay;
  const status = String(mp.status || 'pending');
  if (status === 'approved' && priceNumber(mp.transaction_amount) + 0.001 >= Number(pay.amount)) {
    await env.DB.prepare('UPDATE payments SET mp_id = ? WHERE id = ?').bind(String(mp.id), pay.id).run();
    await applyPayment(env, pay);
    return { ...pay, status: 'approved', applied: 1, mp_id: String(mp.id) };
  }
  if (status !== pay.status && !pay.applied) {
    await env.DB.prepare('UPDATE payments SET status = ?, updated_at = ? WHERE id = ?').bind(status, nowIso(), pay.id).run();
  }
  return { ...pay, status };
}

function paymentPublic(p, extra = {}) {
  return { id: p.id, plan: p.plan, amount: p.amount, method: p.method, status: p.status, approved: !!p.applied, created_at: p.created_at, ...extra };
}

async function handlePayCreate(request, env, account) {
  if (!mpConfigured(env)) throw new HttpError(501, 'O pagamento online está sendo ativado. Tente de novo em alguns minutos.', { code: 'not_configured' });
  const body = await readJson(request);
  const plan = PLANS[body.plan] ? body.plan : 'basic';
  const method = body.method === 'card' ? 'card' : 'pix';
  const amount = priceNumber(planPrice(env, plan));
  if (!(amount > 0)) throw new HttpError(500, 'Preço do plano não configurado.');
  const email = String(body.email || '').trim().toLowerCase();
  if (method === 'pix' && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    throw new HttpError(400, 'Informe um e-mail válido para gerar o Pix (o Mercado Pago envia o comprovante para ele).');
  }
  const ts = nowIso();
  const ref = `vitrine:${account.id}:${plan}:${crypto.randomUUID()}`;
  const base = publicBase(request, env);
  const notify = `${base}/api/mp/webhook`;
  const title = `Vitrine App · Plano ${PLANS[plan].name} (30 dias)`;
  const ins = await env.DB.prepare(
    'INSERT INTO payments (account_id, plan, days, amount, method, ref, status, created_at, updated_at) VALUES (?, ?, 30, ?, ?, ?, ?, ?, ?)',
  ).bind(account.id, plan, amount, method, ref, 'pending', ts, ts).run();
  const payId = ins.meta && ins.meta.last_row_id;

  if (method === 'pix') {
    const mp = await mpFetch(env, '/v1/payments', {
      method: 'POST',
      idem: ref,
      body: {
        transaction_amount: amount,
        description: title,
        payment_method_id: 'pix',
        external_reference: ref,
        notification_url: notify,
        date_of_expiration: new Date(Date.now() + 30 * 60_000).toISOString().replace('Z', '-00:00'),
        payer: { email, first_name: String(account.owner_name || '').split(' ')[0] || undefined },
      },
    });
    await env.DB.prepare('UPDATE payments SET mp_id = ? WHERE id = ?').bind(String(mp.id), payId).run();
    const tx = (mp.point_of_interaction && mp.point_of_interaction.transaction_data) || {};
    return json({
      payment: paymentPublic({ id: payId, plan, amount, method, status: mp.status || 'pending', applied: 0, created_at: ts }),
      pix: { qr_code: tx.qr_code || '', qr_code_base64: tx.qr_code_base64 || '', ticket_url: tx.ticket_url || '', expires_in_min: 30 },
    }, 201);
  }

  const pref = await mpFetch(env, '/checkout/preferences', {
    method: 'POST',
    body: {
      items: [{ id: plan, title, quantity: 1, unit_price: amount, currency_id: 'BRL' }],
      external_reference: ref,
      notification_url: notify,
      back_urls: { success: `${base}/dashboard.html?pago=${payId}`, pending: `${base}/dashboard.html?pago=${payId}`, failure: `${base}/dashboard.html?pago=${payId}` },
      auto_return: 'approved',
      statement_descriptor: 'VITRINEAPP',
      payment_methods: { installments: 1 },
    },
  });
  return json({
    payment: paymentPublic({ id: payId, plan, amount, method, status: 'pending', applied: 0, created_at: ts }),
    checkout_url: pref.init_point,
  }, 201);
}

async function handlePayStatus(env, account, rawId) {
  const pay = await env.DB.prepare('SELECT * FROM payments WHERE id = ? AND account_id = ?').bind(Number(rawId) || 0, account.id).first();
  if (!pay) throw new HttpError(404, 'Pagamento não encontrado.');
  let current = pay;
  if (!pay.applied && mpConfigured(env)) {
    try { current = await syncPayment(env, pay); } catch { /* tenta de novo na próxima consulta */ }
  }
  const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(account.id).first();
  return json({ payment: paymentPublic(current), account: accountPrivate(env, acc) });
}

// Valida a assinatura do aviso (quando MP_WEBHOOK_SECRET está configurado).
async function mpSignatureOk(request, env, dataId) {
  if (!env.MP_WEBHOOK_SECRET) return true;
  const sig = request.headers.get('x-signature') || '';
  const reqId = request.headers.get('x-request-id') || '';
  const parts = Object.fromEntries(sig.split(',').map((kv) => kv.trim().split('=')));
  if (!parts.ts || !parts.v1) return false;
  const manifest = `id:${String(dataId).toLowerCase()};request-id:${reqId};ts:${parts.ts};`;
  const key = await crypto.subtle.importKey('raw', enc.encode(env.MP_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(manifest)));
  const hex = [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
  return timingSafeEqual(enc.encode(hex), enc.encode(String(parts.v1)));
}

// Aviso do Mercado Pago. Nunca confia no conteúdo: sempre consulta o pagamento direto no Mercado Pago.
async function handleMpWebhook(request, env) {
  if (!mpConfigured(env)) return json({ ok: true });
  const url = new URL(request.url);
  const body = await request.json().catch(() => ({}));
  const type = body.type || body.topic || url.searchParams.get('type') || url.searchParams.get('topic') || '';
  const dataId = (body.data && body.data.id) || url.searchParams.get('data.id') || url.searchParams.get('id') || '';
  if (!/payment/.test(type) || !/^\d+$/.test(String(dataId))) return json({ ok: true });
  if (!(await mpSignatureOk(request, env, dataId))) return json({ error: 'assinatura inválida' }, 401);
  let mp;
  try { mp = await mpFetch(env, `/v1/payments/${dataId}`); } catch { return json({ ok: true }); } // o painel confere de novo sozinho
  const ref = String(mp.external_reference || '');
  if (!ref.startsWith('vitrine:')) return json({ ok: true }); // pagamento de outro sistema (ex.: Nexus)
  const pay = await env.DB.prepare('SELECT * FROM payments WHERE ref = ?').bind(ref).first();
  if (pay) await syncPayment(env, pay, mp);
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
  if ((m = path.match(/^\/api\/store\/([^/]+)$/)) && method === 'GET') return handleStore(request, env, decodeURIComponent(m[1]));
  if ((m = path.match(/^\/api\/photo\/([psc])\/([^/]+)$/)) && method === 'GET') return handlePhoto(env, m[1], decodeURIComponent(m[2]).toLowerCase());
  if ((m = path.match(/^\/api\/images\/(.+)$/)) && method === 'GET') return handleImage(env, decodeURIComponent(m[1]));
  if (path === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
  if (path === '/api/auth/register' && method === 'POST') return handleRegister(request, env);
  if (path === '/api/auth/check-slug' && method === 'GET') return handleCheckSlug(env, new URL(request.url));

  if (path === '/api/me' || path.startsWith('/api/me/')) {
    const account = await requireAccount(request, env);
    if (path === '/api/me/ping' && method === 'POST') return handlePing(env, account);
    if (path === '/api/me/password' && method === 'PUT') return handlePassword(request, env, account);
    if (path === '/api/me/stores' && method === 'GET') return handleStores(request, env, account);
    if (path === '/api/me/pay' && method === 'POST') return handlePayCreate(request, env, account);
    if ((m = path.match(/^\/api\/me\/pay\/(\d+)$/)) && method === 'GET') return handlePayStatus(env, account, m[1]);
    if (path === '/api/me/stores' && method === 'POST') return handleCreateStore(request, env, account);
    if ((m = path.match(/^\/api\/me\/stores\/([^/]+)$/)) && method === 'DELETE') {
      return handleDeleteStore(env, account, decodeURIComponent(m[1]));
    }
    const tenant = await requireStore(request, env, account);
    if (path === '/api/me' && method === 'GET') return handleMe(request, env, tenant);
    if (path === '/api/me/lookup' && method === 'POST') return handleLookup(request, env, tenant);
    if (path === '/api/me/profile' && method === 'PUT') return handleProfile(request, env, tenant);
    if (path === '/api/me/settings' && method === 'PUT') return handleSettings(request, env, tenant);
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
  if (path === '/api/mp/webhook' && (method === 'POST' || method === 'GET')) return handleMpWebhook(request, env);

  if (path === '/api/admin' || path.startsWith('/api/admin/')) {
    await requireMaster(request, env);
    if (path === '/api/admin/ml/start' && method === 'POST') return handleMlStart(request, env);
    if (path === '/api/admin/ml/affiliate' && method === 'POST') return handleMlAffiliate(request, env);
    if (path === '/api/admin/ml/affiliate' && method === 'GET') {
      const cfg = await getConfig(env);
      return json({ params: JSON.parse(cfg.ml_affiliate_params || '{}'), connected: mlConfigured(env) && !!cfg.ml_tokens });
    }
    if (path === '/api/admin/ml/search' && method === 'POST') return handleMlSearch(request, env);
    if (path === '/api/admin/ml/disconnect' && method === 'POST') {
      await env.DB.prepare("DELETE FROM app_config WHERE key IN ('ml_tokens', 'ml_nickname')").run();
      return json({ ok: true });
    }
    if ((path === '/api/admin/tenants' || path === '/api/admin/accounts') && method === 'GET') return handleAdminList(request, env);
    if ((path === '/api/admin/tenants' || path === '/api/admin/accounts') && method === 'POST') return handleAdminCreate(request, env);
    if (path === '/api/admin/config' && method === 'GET') return handleAdminConfigGet(env);
    if (path === '/api/admin/config' && method === 'PUT') return handleAdminConfigPut(request, env);
    if (path === '/api/admin/integrations/test' && method === 'POST') {
      const body = await readJson(request);
      return json({ product: await lookupProduct(env, body.url, { useCache: false }) });
    }
    if ((m = path.match(/^\/api\/admin\/(?:tenants|accounts)\/([^/]+)$/))) {
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
    `SELECT t.id, t.store_name, t.owner_name, t.avatar_url, t.theme_color,
            COALESCE(a.status, t.status) AS status, COALESCE(a.trial_ends_at, t.trial_ends_at) AS trial_ends_at,
            COALESCE(a.paid_until, t.paid_until) AS paid_until
       FROM tenants t LEFT JOIN accounts a ON a.id = t.account_id WHERE t.id = ?`,
  ).bind(slug).first();
  if (!t) return null;
  const meta = {
    title: `${t.store_name} | Vitrine App`,
    description: `Confira os produtos da vitrine ${t.store_name}.`,
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
