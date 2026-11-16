# Vitrine App: SaaS de vitrines de produtos (multi-lojista)

Com a Vitrine, lojistas, criadores de conteúdo e afiliados montam a própria vitrine em `/s/<loja>`. A loja recebe 7 dias de teste automáticos e, depois disso, passa ao plano de R$ 19,90/mês.

## Estrutura

| Arquivo | O que faz |
|---|---|
| `schema.sql` | Tabelas do D1: `tenants`, `products`, `tenant_settings` |
| `worker/index.js` | API completa (Cloudflare Worker, ES Modules) e a prévia Open Graph de `/s/<loja>` |
| `public/index.html` | Vitrine pública do lojista (`/s/<loja>` ou `/?loja=<loja>`) |
| `public/dashboard.html` | Painel do lojista: produtos, fotos, configurações, perfil e senha |
| `public/admin.html` | Painel Master: lojas, testes, ativação, cobrança, senha e exclusão |
| `public/config.js` | Endereço da API, usado só quando o site e a API ficam em domínios diferentes |
| `functions/` | Rotas do Cloudflare Pages (`/api/*` e `/s/<loja>`), que usam o `worker/index.js` |
| `wrangler.toml` | Configuração do Pages: pasta `public`, banco D1 e variáveis |

## Publicar no Cloudflare Pages

O `wrangler.toml` já informa ao Pages a pasta publicada (`public`), o banco D1 `minhavitrine` e as variáveis.

1. *Workers & Pages → Create → **Pages** → Connect to Git* → repositório `vitrineapp`.
2. **Project name:** `vitrineapp` → o site fica em `https://vitrineapp.pages.dev`.
3. *Framework preset:* **None** · *Build command:* vazio · *Build output directory:* **`public`** → **Save and Deploy**.
4. *Settings → Variables and Secrets* → crie como **Secret**: `MASTER_PASSWORD` e `SESSION_SECRET` (texto longo aleatório).
5. *Deployments → ⋯ → Retry deployment* (os segredos só valem após um novo deploy).
6. Teste: `/api/health`, depois `/admin.html`.

As tabelas do banco já foram criadas. Para recriar em outro banco: `npm run db:init`.

### Fotos no R2 (opcional, recomendado)
Crie o bucket `vitrine-imagens` no painel R2 e descomente o bloco `[[r2_buckets]]` do `wrangler.toml`. O painel detecta sozinho.

## Fluxo de uso
1. No **Master** (`/admin.html`), crie a loja. Ela começa automaticamente com 7 dias de teste. Os dados de acesso podem ser enviados ao lojista com um toque, pelo WhatsApp.
2. O **lojista** entra em `/dashboard.html`, cadastra os produtos e configura a vitrine.
3. O **cliente final** acessa `/s/<loja>` e compra pelo link do produto ou compartilha o produto no WhatsApp.
4. Quando o teste vence, o status muda sozinho para `expired`: a vitrine sai do ar e a edição fica pausada, mas os produtos continuam salvos. No Master, a opção **Ativar plano** (30, 90, 180 ou 365 dias) devolve tudo na hora.

## API

Rotas públicas:
- `GET /api/store/:tenantId`: lojista, configurações, produtos e situação do teste. Atualiza o status para `expired` quando o prazo venceu e não envia o preço quando o lojista escolheu ocultá-lo.
- `GET /api/config`
- `POST /api/auth/login`

Rotas do lojista (`Authorization: Bearer`):
- `GET /api/me`
- `PUT /api/me/profile`, `PUT /api/me/settings`, `PUT /api/me/password`
- `POST /api/me/upload`
- `POST|PUT|DELETE /api/me/products[/:id]`

Rotas do Master (`X-Master-Password`):
- `GET|POST /api/admin/tenants`
- `PATCH /api/admin/tenants/:id`, com `action`: `activate | extend_trial | expire | reset_password | update`
- `DELETE /api/admin/tenants/:id`

## Segurança
- As senhas dos lojistas são guardadas com PBKDF2-SHA256 (100 mil iterações e salt aleatório).
- O login gera um token assinado com HMAC, válido por 30 dias. Trocar a senha desconecta os outros aparelhos.
- A loja de cada lojista vem sempre do token, nunca de um parâmetro da requisição.
- A senha Master é comparada em tempo constante. Ela fica em memória e na sessão da aba, nunca no armazenamento local permanente.
- Links e imagens aceitam só `http(s)`, ou imagem em base64 no caso das fotos. Todo texto é escapado ao ser exibido na tela.
- Antes de divulgar o painel Master, vale ativar uma regra de *Rate Limiting* (WAF da Cloudflare) para `/api/auth/login` e `/api/admin/*`.

## Próximos passos sugeridos
- Cobrança automática (Pix ou assinatura do Mercado Pago com webhook), para a ativação deixar de ser manual.
- Cadastro self-service dos lojistas, com teste automático.
- Contagem de cliques por produto, para mostrar no painel.
