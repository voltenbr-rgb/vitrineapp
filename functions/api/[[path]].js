// Adaptador para Cloudflare Pages Functions: toda rota /api/* usa a mesma API do Worker.
// No Pages, configure em Settings → Bindings: D1 "DB" (e opcionalmente R2 "IMAGES"),
// e em Variables and Secrets: MASTER_PASSWORD, SESSION_SECRET, PLAN_PRICE, SUPPORT_WHATSAPP.
import worker from '../../worker/index.js';

export const onRequest = (context) => worker.fetch(context.request, context.env, context);
