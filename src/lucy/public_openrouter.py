"""Bounded OpenRouter JSON adapter for Public Lucy model evaluation."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lucy.public_model import PublicModelCall, PublicModelCompletion

_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"


class OpenRouterPublicError(RuntimeError):
    """The provider call failed without exposing prompt or response content."""


class OpenRouterUsage(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    cost: float = Field(ge=0)


class OpenRouterMessage(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    content: str = Field(min_length=1)


class OpenRouterChoice(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    message: OpenRouterMessage


class OpenRouterResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    choices: tuple[OpenRouterChoice, ...] = Field(min_length=1)
    usage: OpenRouterUsage


class OpenRouterPublicJsonModel:
    """Call one exact model through ZDR/data-collection-denied routing."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        allowed_providers: tuple[str, ...] = (),
        maximum_prompt_usd_per_million: float,
        maximum_completion_usd_per_million: float,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if not 20 <= len(api_key) <= 2_000:
            raise ValueError("OpenRouter credential is invalid")
        if not model or len(model) > 200 or model.startswith("~"):
            raise ValueError("OpenRouter model must be an exact public identifier")
        if any(not provider or len(provider) > 100 for provider in allowed_providers):
            raise ValueError("OpenRouter provider allowlist is invalid")
        if maximum_prompt_usd_per_million <= 0 or maximum_completion_usd_per_million <= 0:
            raise ValueError("OpenRouter price ceilings must be positive")
        self._api_key = api_key
        self._model = model
        self._providers = allowed_providers
        self._maximum_prompt = maximum_prompt_usd_per_million
        self._maximum_completion = maximum_completion_usd_per_million
        self._referer = (environment or {}).get(
            "LUCY_PUBLIC_MODEL_REFERER", "https://www.utopiahomes.com"
        )

    def complete(self, call: PublicModelCall) -> PublicModelCompletion:
        provider: dict[str, object] = {
            "zdr": True,
            "data_collection": "deny",
            "allow_fallbacks": False,
            "max_price": {
                "prompt": self._maximum_prompt,
                "completion": self._maximum_completion,
            },
        }
        if self._providers:
            provider["only"] = list(self._providers)
        body: dict[str, object] = {
            "model": self._model,
            "messages": [message.model_dump(mode="json") for message in call.messages],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": call.response_schema_name,
                    "strict": True,
                    "schema": call.response_schema,
                },
            },
            "provider": provider,
        }
        if self._model.startswith("openai/gpt-5"):
            body["max_completion_tokens"] = call.max_output_tokens
            body["reasoning"] = {"effort": "low", "exclude": True}
        else:
            body["max_tokens"] = call.max_output_tokens
        request = Request(
            _ENDPOINT,
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": self._referer,
                "X-Title": "Utopia Public Lucy evaluation",
            },
        )
        try:
            with urlopen(request, timeout=call.timeout_seconds) as response:  # noqa: S310
                raw = response.read(1_000_001)
        except HTTPError as exc:
            raise OpenRouterPublicError(f"OpenRouter returned HTTP {exc.code}") from None
        except (TimeoutError, URLError):
            raise OpenRouterPublicError("OpenRouter request was unavailable") from None
        if len(raw) > 1_000_000:
            raise OpenRouterPublicError("OpenRouter response exceeded its bound")
        try:
            result = OpenRouterResponse.model_validate_json(raw)
        except (ValidationError, ValueError):
            raise OpenRouterPublicError("OpenRouter returned an invalid response") from None
        if result.model != self._model:
            raise OpenRouterPublicError("OpenRouter returned a different model")
        incurred = math.ceil(result.usage.cost * 1_000_000)
        if incurred > call.maximum_microusd:
            raise OpenRouterPublicError("OpenRouter charge exceeded the admitted request bound")
        return PublicModelCompletion(
            content=result.choices[0].message.content,
            model=result.model,
            provider=result.provider,
            provider_reference=result.id,
            prompt_tokens=result.usage.prompt_tokens,
            completion_tokens=result.usage.completion_tokens,
            incurred_microusd=incurred,
        )
