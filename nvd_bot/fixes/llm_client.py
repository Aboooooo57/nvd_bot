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
        import litellm

        provider = self.active_provider()
        if provider != config.get('llm_provider', 'openrouter'):
            print('[llm] Auto-detected litellm_proxy (LITELLM_BASE_URL set, no OPENROUTER_API_KEY)')

        model = model_override or config.get('llm_model', 'openrouter/anthropic/claude-3-haiku')
        max_tok = max_tokens or config.get('llm_max_tokens', 2000)

        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': user_prompt})

        kwargs: dict = {
            'messages': messages,
            'max_tokens': max_tok,
        }

        if provider == 'openrouter':
            if config.OPENROUTER_API_KEY:
                kwargs['api_key'] = config.OPENROUTER_API_KEY
                kwargs['api_base'] = 'https://openrouter.ai/api/v1'
            kwargs['model'] = model
        elif provider == 'litellm_proxy':
            if config.LITELLM_API_KEY:
                kwargs['api_key'] = config.LITELLM_API_KEY
            if config.LITELLM_BASE_URL:
                kwargs['api_base'] = config.LITELLM_BASE_URL
            kwargs['model'] = model
            print(f'[llm] litellm_proxy: model="{model}" → {config.LITELLM_BASE_URL}')

        try:
            response = litellm.completion(**kwargs)
            return response.choices[0].message.content or ''
        except Exception as e:
            print(f'[llm] Generation failed: {e}')
            raise

    def chat(self, messages: list[dict], max_tokens: int | None = None,
             model_override: str | None = None) -> str:
        """Call the LLM with a pre-built OpenAI-format messages list (multi-turn)."""
        import litellm
        provider = self.active_provider()
        model = model_override or config.get('llm_model', 'gemini-3.5-flash')
        max_tok = max_tokens or config.get('llm_max_tokens', 2000)
        kwargs: dict = {'messages': messages, 'max_tokens': max_tok}
        if provider == 'openrouter':
            if config.OPENROUTER_API_KEY:
                kwargs['api_key'] = config.OPENROUTER_API_KEY
                kwargs['api_base'] = 'https://openrouter.ai/api/v1'
            kwargs['model'] = model
        elif provider == 'litellm_proxy':
            if config.LITELLM_API_KEY:
                kwargs['api_key'] = config.LITELLM_API_KEY
            if config.LITELLM_BASE_URL:
                kwargs['api_base'] = config.LITELLM_BASE_URL
            kwargs['model'] = model
        try:
            response = litellm.completion(**kwargs)
            return response.choices[0].message.content or ''
        except Exception as e:
            print(f'[llm] Chat failed: {e}')
            raise
