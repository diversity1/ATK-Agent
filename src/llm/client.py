import config

class LLMClient:
    def __init__(self):
        self.provider = config.LLM_PROVIDER
        self.model = config.LLM_MODEL
        self.api_key = config.LLM_API_KEY
        self.api_base = config.LLM_API_BASE
        
        self.openai_client = None
        if config.ENABLE_LLM and self.api_key and self.provider == "openai":
            try:
                from openai import OpenAI
                self.openai_client = OpenAI(api_key=self.api_key, base_url=self.api_base if self.api_base else None)
            except Exception:
                pass

    def is_available(self) -> bool:
        if not config.ENABLE_LLM:
            return False
        if self.provider == "openai" and self.openai_client:
            return True
        return False

    def chat(self, messages: list, model: str = None, temperature: float = 0) -> str:
        if not self.is_available():
            raise Exception("LLM is not available")
            
        if self.provider == "openai":
            import requests
            
            clean_api_key = self.api_key.strip().encode('ascii', 'ignore').decode('ascii')
            
            headers = {
                "Authorization": f"Bearer {clean_api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model or self.model,
                "messages": messages,
                "temperature": temperature
            }
            url = f"{self.api_base.rstrip('/')}/chat/completions" if self.api_base else "https://api.openai.com/v1/chat/completions"
            
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
            if resp.status_code != 200:
                raise Exception(f"API Error {resp.status_code}: {resp.text}")
                
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        
        raise NotImplementedError(f"Provider {self.provider} not fully implemented")
