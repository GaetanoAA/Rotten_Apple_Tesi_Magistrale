from pydantic import BaseModel, Field
from typing import Literal


class AgentOutput(BaseModel):
    verdict: Literal["APPROVE", "REJECT"]

    rationale_public: str = Field(
        description="Motivazione pubblica breve della decisione."
    )

    summary: str = Field(
        description="Sintesi concisa dell'analisi dell'agente."
    )

    cited_object_ids: list[str] = Field(
        default_factory=list,
        description="ID degli oggetti esplicitamente citati."
    )

    decision_basis_ids: list[str] = Field(
        default_factory=list,
        description="ID degli oggetti usati come base della decisione."
    )

    confidence_claimed: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidenza dichiarata tra 0 e 1."
    )