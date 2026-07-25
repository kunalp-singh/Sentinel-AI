from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.domain.enums import EntityType


class Entity(BaseModel):
    """An identity or device monitored by SentinelAI."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    entity_id: str = Field(min_length=3, max_length=64)
    entity_type: EntityType
    peer_group: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(
    default_factory=lambda: datetime.now(UTC)
    )

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, value: str) -> str:
        allowed = set(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789_-"
        )

        if not all(character in allowed for character in value):
            raise ValueError(
                "entity_id may contain only letters, numbers, '_' and '-'"
            )

        return value