from typing import Any

class Registry:
    _instances = {}

    @classmethod
    def register(cls, name: str, instance: Any):
        cls._instances[name] = instance

    @classmethod
    def get(cls, name: str) -> Any:
        return cls._instances.get(name)

    @classmethod
    def clear(cls):
        cls._instances.clear()

registry = Registry()
