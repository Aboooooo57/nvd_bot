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
        provider = self.active_provider()
        if provider != config.get('llm_provider', 'openrouter'):
            print('[llm] Auto-detected litellm_proxy (LITELLM_BASE_URL set, no OPENROUTER_API_KEY)')

        model = model_override or config.get('llm_model', 'openrouter/anthropic/claude-3-haiku')
        max_tok = max_tokens or config.get('llm_max_tokens', 2000)

        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': user_prompt})

        if provider == 'litellm_proxy':
            # Use the OpenAI client directly so the model name is sent as-is.
            # litellm.completion() rewrites provider-prefixed model names (e.g.
            # strips gemini/ before forwarding), which breaks proxy key validation.
            import openai
            base_url = (config.LITELLM_BASE_URL or '').rstrip('/')
            api_key = config.LITELLM_API_KEY or 'sk-placeholder'
            print(f'[llm] litellm_proxy: model="{model}" → {base_url}')
            client = openai.OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tok,
            )
            return response.choices[0].message.content or ''

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
