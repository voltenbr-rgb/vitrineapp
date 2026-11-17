-- =====================================================================
-- Vitrine App — SaaS multi-tenant de vitrines de produtos
-- Banco: Cloudflare D1 (SQLite)
--
-- Aplicar:
--   npx wrangler d1 execute minhavitrine --remote --file=schema.sql
-- (use --local para o banco de desenvolvimento)
--
-- Bancos criados por versões anteriores são atualizados sozinhos pela API
-- (colunas novas e a tabela app_config são adicionadas no primeiro acesso).
--
-- Datas são gravadas em ISO 8601 UTC (ex.: 2026-11-16T04:15:00.000Z),
-- o que permite comparar datas como texto com segurança.
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- Lojistas (inquilinos). O id é o slug público: /s/loja-do-joao
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id             TEXT PRIMARY KEY
                 CHECK (length(id) BETWEEN 3 AND 40),
  store_name     TEXT NOT NULL,
  owner_name     TEXT NOT NULL DEFAULT '',
  whatsapp       TEXT NOT NULL DEFAULT '',            -- só dígitos, com DDI (5567999999999)
  avatar_url     TEXT,
  cover_url      TEXT,                                -- foto de capa (fundo do topo da vitrine)
  theme_color    TEXT NOT NULL DEFAULT '#16a6e0',     -- #RRGGBB
  password_hash  TEXT NOT NULL,                       -- pbkdf2$iteracoes$salt$hash
  status         TEXT NOT NULL DEFAULT 'trial'
                 CHECK (status IN ('trial', 'active', 'expired')),
  trial_ends_at  TEXT NOT NULL,                       -- created_at + 7 dias (calculado na criação)
  paid_until     TEXT,                                -- validade do plano pago (R$ 19,90/mês)
  last_seen_at   TEXT,                                -- último sinal do painel (online no Master)
  last_login_at  TEXT,
  views          INTEGER NOT NULL DEFAULT 0,          -- visitas à vitrine pública
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_tenants_status_trial ON tenants (status, trial_ends_at);
CREATE INDEX IF NOT EXISTS idx_tenants_created      ON tenants (created_at);

-- ---------------------------------------------------------------------
-- Produtos de cada lojista
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id        TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  title            TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  price            REAL,                              -- opcional (afiliados podem omitir)
  image_url        TEXT,
  affiliate_link   TEXT,                              -- obrigatório para mercadolivre/shopee
  platform         TEXT NOT NULL DEFAULT 'proprio'
                   CHECK (platform IN ('mercadolivre', 'shopee', 'proprio')),
  is_physical      INTEGER NOT NULL DEFAULT 0 CHECK (is_physical IN (0, 1)),
  delivery_cities  TEXT NOT NULL DEFAULT '',          -- ex.: "Campo Grande, Dourados"
  sort_order       INTEGER NOT NULL DEFAULT 0,
  is_visible       INTEGER NOT NULL DEFAULT 1 CHECK (is_visible IN (0, 1)),  -- 0 = oculto para os clientes
  show_price       INTEGER NOT NULL DEFAULT 1 CHECK (show_price IN (0, 1)),  -- 0 = preço deste produto oculto
  original_price   REAL,                              -- preço antigo ("De"), para mostrar o desconto
  category         TEXT NOT NULL DEFAULT '',          -- categoria livre (filtro na vitrine)
  price_checked_at TEXT,                              -- última conferência automática do preço (afiliados, 1x/dia)
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_products_tenant ON products (tenant_id, sort_order, id);

-- ---------------------------------------------------------------------
-- O que o cliente final vê na vitrine
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id           TEXT PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
  show_prices         INTEGER NOT NULL DEFAULT 1 CHECK (show_prices IN (0, 1)),
  show_stock_warning  INTEGER NOT NULL DEFAULT 1 CHECK (show_stock_warning IN (0, 1)),
  view_mode           TEXT NOT NULL DEFAULT 'grid' CHECK (view_mode IN ('grid', 'list')),
  show_banner         INTEGER NOT NULL DEFAULT 1,     -- 0 = cliente vê só os produtos
  share_message       TEXT NOT NULL DEFAULT '',       -- mensagem pronta personalizada ({loja} e {link})
  offer_template      INTEGER NOT NULL DEFAULT 1      -- modelo de mensagem de oferta (1 a 3)
);

-- ---------------------------------------------------------------------
-- Configurações do sistema (vídeo da página inicial, WhatsApp de suporte,
-- senha Master personalizada, segredo de sessão gerado automaticamente)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_config (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  TEXT
);
