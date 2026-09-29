/**
 * AI provider abstraction.
 * - LLM adapters (OpenAI-compatible, Anthropic) activate only when their
 *   credentials are configured (env MERIDIAN_AI_*). They are called through
 *   this single interface with grounded context.
 * - The local "grounded synthesis" provider is deterministic: it composes
 *   answers exclusively from supplied evidence and always cites sources.
 *   It never fabricates measurements or tool output.
 */
export class LlmProvider {
  get name() { return 'abstract'; }
  async complete({ system, prompt, context }) { throw new Error('not implemented'); }
}

export class LocalGroundedProvider extends LlmProvider {
  get name() { return 'local-grounded-rules-v1'; }
  /**
   * Deterministic grounded answer composition.
   * @param {string} prompt the question
   * @param {Array<{id:string, text:string, source:string}>} context evidence chunks (pre-retrieved)
   */
  async complete({ prompt, context }) {
    if (!context || !context.length) {
      return {
        provider: this.name,
        answer: 'No evidence is available in the selected knowledge base to answer this question. Add documents to the knowledge base or rephrase the question.',
        citations: [],
        grounded: true,
        note: 'refusal_due_to_no_evidence',
      };
    }
    // rank context chunks by term overlap with the question
    const qTerms = new Set(prompt.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2));
    const scored = context.map((c) => {
      const terms = c.text.toLowerCase().split(/[^a-z0-9]+/);
      const hits = terms.filter((t) => qTerms.has(t)).length;
      return { c, hits, density: hits / Math.max(1, terms.length) };
    }).sort((a, b) => b.hits - a.hits || b.density - a.density);
    const best = scored.filter((s) => s.hits > 0).slice(0, 4);
    const usable = best.length ? best : scored.slice(0, 2);
    const answerParts = [];
    for (const { c } of usable) {
      // extract the most relevant sentence(s)
      const sentences = c.text.split(/(?<=[.!?])\s+/).filter((s) => s.trim());
      const rel = sentences.filter((s) => s.toLowerCase().split(/[^a-z0-9]+/).some((t) => qTerms.has(t)));
      const chosen = (rel.length ? rel : sentences.slice(0, 1)).slice(0, 2).join(' ');
      answerParts.push({ text: chosen.trim(), citation: c.id, source: c.source });
    }
    const confidence = best.length ? (best[0].hits >= 3 ? 'high' : 'medium') : 'low';
    return {
      provider: this.name,
      answer: answerParts.map((p) => p.text).join(' '),
      citations: answerParts.map((p) => ({ id: p.citation, source: p.source, quote: p.text.slice(0, 160) })),
      grounded: true,
      confidence,
      note: best.length ? null : 'low_term_overlap_answer_based_on_top_documents',
    };
  }
}

export class OpenAiCompatibleProvider extends LlmProvider {
  constructor({ baseUrl, apiKey, model }) {
    super();
    this.baseUrl = baseUrl || 'https://api.openai.com/v1';
    this.apiKey = apiKey;
    this.model = model || 'gpt-4o-mini';
  }
  get name() { return `openai-compatible:${this.model}`; }
  async complete({ system, prompt, context }) {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.model,
        messages: [
          { role: 'system', content: system || 'You answer strictly from the provided context. Cite evidence ids like [chunk:id]. If the context is insufficient, say so.' },
          { role: 'user', content: `Context:\n${(context || []).map((c) => `[${c.id}] ${c.text}`).join('\n---\n')}\n\nQuestion: ${prompt}` },
        ],
        temperature: 0.1,
      }),
    });
    if (!res.ok) throw new Error(`LLM provider error: HTTP ${res.status}`);
    const data = await res.json();
    return { provider: this.name, answer: data.choices?.[0]?.message?.content || '', citations: (context || []).map((c) => ({ id: c.id, source: c.source })), grounded: true, model: this.model };
  }
}

export function resolveProvider(env = process.env) {
  if (env.MERIDIAN_AI_API_KEY) {
    return new OpenAiCompatibleProvider({
      baseUrl: env.MERIDIAN_AI_BASE_URL,
      apiKey: env.MERIDIAN_AI_API_KEY,
      model: env.MERIDIAN_AI_MODEL,
    });
  }
  return new LocalGroundedProvider();
}
