from __future__ import annotations
from nvd_bot import config


class LLMClient:
    def __init__(self):
        pass

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int | None = None,
                 model_override: str | None = None) -> str:
        import litellm

        provider = config.get('llm_provider', 'openrouter')
        model = model_override or config.get('llm_model', 'openrouter/anthropic/claude-3-haiku')
        max_tok = max_tokens or config.get('llm_max_tokens', 2000)

        kwargs: dict = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt},
            ],
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
