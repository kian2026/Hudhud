from typing import Optional

from pydantic import BaseModel, Field


class HudhudType(BaseModel):
    """Base class for all Hudhud entity types with nodeLabel support.
    nodeLabel is optional but computed at definition time.

    All classes that inherit from HudhudType must be decorated with @hudhud_type
    to be registered in the global TYPE_REGISTRY and accessed by their class name.

    Usage:
        from hudhud_types.registry import hudhud_type

        @hudhud_type
        class Domain(HudhudType):
            domain: str
    """

    nodeLabel: Optional[str] = Field(
        None,
        description="UI-readable label for this entity, the one used on the graph.",
        title="Label",
    )

    # Allow extra keys to support for additional properties from user
    class ConfigDict:
        extra = "allow"
