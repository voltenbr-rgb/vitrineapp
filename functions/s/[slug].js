// Adaptador para Cloudflare Pages Functions: /s/<slug> abre a vitrine com prévia (Open Graph) da loja.
import worker from '../../worker/index.js';

export const onRequest = (context) => worker.fetch(context.request, context.env, context);
