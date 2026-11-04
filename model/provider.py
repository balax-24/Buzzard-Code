from abc import ABC, abstractmethod
from typing import List, Dict, Any, Generator, Optional

class ModelProvider(ABC):
    """
    Abstract base class representing an interface to a local or remote LLM provider.
    BUZZARD CODE OWNS EXECUTION AND SECURITY. THE MODEL IS REPLACEABLE.
    """

    @abstractmethod
    def generate(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None, 
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generates a text completion for a single prompt.
        """
        pass

    @abstractmethod
    def chat(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sends a full message history and returns the model response.
        Expected return format: {"message": {"role": "assistant", "content": "..."}}
        """
        pass

    @abstractmethod
    def stream_chat(
        self, 
        messages: List[Dict[str, Any]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Streams a chat response token by token.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Checks if the provider service is running and reachable.
        """
        pass

    @abstractmethod
    def get_available_models(self) -> List[str]:
        """
        Returns a list of models available under this provider.
        """
        pass

    def list_models(self) -> List[str]:
        """Alias for get_available_models."""
        return self.get_available_models()

    def health_check(self) -> Dict[str, Any]:
        """
        Performs a health check on the provider.
        Returns a dictionary with status ("ok" | "error"), provider, and details.
        """
        available = self.is_available()
        return {
            "status": "ok" if available else "error",
            "available": available,
            "models_count": len(self.get_available_models()) if available else 0
        }

    def capabilities(self) -> Dict[str, Any]:
        """
        Returns feature capabilities supported by this provider.
        """
        return {
            "streaming": True,
            "chat": True,
            "tools": True,
            "local": False
        }
