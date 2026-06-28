from __future__ import annotations
from nvd_bot import config


class LLMClient:
    def __init__(self):
        pass

    def active_provider(self) -> str:
        """Return the provider that will actually be used, applying auto-detection."""
        if not config.OPENROUTER_API_KEY and (config.LITELLM_BASE_URL or config.LITELLM_API_KEY):
            return 'litellm_proxy'
        return config.get('llm_provider', 'openrouter')

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int | None = None,
                 model_override: str | None = None) -> str:
        """Single-shot helper: build a 1-2 message list and return the reply."""
        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': user_prompt})
        return self.chat(messages, max_tokens=max_tokens, model_override=model_override)

    def chat(self, messages: list[dict],
             max_tokens: int | None = None,
             model_override: str | None = None) -> str:
        """Multi-turn completion: send a full message list, return the assistant text."""
        provider = self.active_provider()
        if provider != config.get('llm_provider', 'openrouter'):
            print('[llm] Auto-detected litellm_proxy (LITELLM_BASE_URL set, no OPENROUTER_API_KEY)')

        model = model_override or config.get('llm_model', 'openrouter/anthropic/claude-3-haiku')
        max_tok = max_tokens or config.get('llm_max_tokens', 2000)

        if provider == 'litellm_proxy':
            # Call the proxy with plain HTTP, mimicking a raw curl. The openai SDK
            # attaches User-Agent + X-Stainless-* headers that the proxy's WAF blocks
            # ("Your request was blocked"); curl/requests avoid them. See
            # github.com/openai/openai-python/issues/2879. This also sends the model
            # name as-is, so provider-prefixed names (gemini/...) are preserved.
            import requests
            base_url = (config.LITELLM_BASE_URL or '').rstrip('/')
            url = f'{base_url}/chat/completions'
            headers = {'Content-Type': 'application/json'}
            if config.LITELLM_API_KEY:
                headers['Authorization'] = f'Bearer {config.LITELLM_API_KEY}'
            payload = {'model': model, 'messages': messages, 'max_tokens': max_tok}
            print(f'[llm] litellm_proxy: model="{model}" → {url}')
            r = requests.post(url, headers=headers, json=payload, timeout=120)
            if r.status_code != 200:
                try:
                    err_obj = r.json().get('error', {})
                    err_type = err_obj.get('type', '')
                    err_msg  = err_obj.get('message', r.text[:200])
                except Exception:
                    err_type, err_msg = '', r.text[:200]
                if err_type == 'expired_key':
                    raise RuntimeError(
                        'LiteLLM Key Expired — generate a new key in the LiteLLM '
                        'admin panel and update LITELLM_API_KEY in your .env'
                    )
                raise RuntimeError(f'litellm_proxy {r.status_code}: {err_msg}')
            data = r.json()
            return data['choices'][0]['message'].get('content') or ''

        # OpenRouter (and any other litellm-routed provider)
        import litellm
        kwargs: dict = {'messages': messages, 'max_tokens': max_tok}
        if provider == 'openrouter':
            if config.OPENROUTER_API_KEY:
                kwargs['api_key'] = config.OPENROUTER_API_KEY
                kwargs['api_base'] = 'https://openrouter.ai/api/v1'
            kwargs['model'] = model

        try:
            response = litellm.completion(**kwargs)
            return response.choices[0].message.content or ''
        except Exception as e:
            print(f'[llm] Generation failed: {e}')
            raise
