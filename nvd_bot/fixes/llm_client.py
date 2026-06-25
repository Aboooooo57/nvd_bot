from __future__ import annotations
from nvd_bot import config


class LLMClient:
    def __init__(self):
        pass

    def active_provider(self) -> str:
        """Return the provider that will actually be used, applying auto-detection."""
        provider = config.get('llm_provider', 'openrouter')
        if provider == 'openrouter' and not config.OPENROUTER_API_KEY and config.LITELLM_BASE_URL:
            return 'litellm_proxy'
        return provider

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int | None = None,
                 model_override: str | None = None) -> str:
        import litellm

        provider = self.active_provider()
        if provider != config.get('llm_provider', 'openrouter'):
            print('[llm] Auto-detected litellm_proxy (LITELLM_BASE_URL set, no OPENROUTER_API_KEY)')

        model = model_override or config.get('llm_model', 'openrouter/anthropic/claude-3-haiku')
        max_tok = max_tokens or config.get('llm_max_tokens', 2000)

        # Warn if model looks like an OpenRouter-format model but we're using LiteLLM proxy
        if provider == 'litellm_proxy' and model.startswith('openrouter/') and not model_override:
            print(f'[llm] Warning: model "{model}" has openrouter/ prefix but provider is litellm_proxy. '
                  'Use /setconfig llm_model <your-litellm-model-name> to fix.')

        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': user_prompt})

        kwargs: dict = {
            'model': model,
            'messages': messages,
            'max_tokens': max_tok,
        }

        if provider == 'openrouter':
            if config.OPENROUTER_API_KEY:
                kwargs['api_key'] = config.OPENROUTER_API_KEY
                kwargs['api_base'] = 'https://openrouter.ai/api/v1'
        elif provider == 'litellm_proxy':
            if config.LITELLM_API_KEY:
                kwargs['api_key'] = config.LITELLM_API_KEY
            if config.LITELLM_BASE_URL:
                kwargs['api_base'] = config.LITELLM_BASE_URL

        try:
            response = litellm.completion(**kwargs)
            return response.choices[0].message.content or ''
        except Exception as e:
            print(f'[llm] Generation failed: {e}')
            raise
