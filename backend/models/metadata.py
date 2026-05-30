from pydantic import BaseModel, Field
from typing import Optional, Any


class SecurityDocMetadata(BaseModel):
    framework: str = Field(..., description="e.g. nextjs, supabase, prisma, express, react, firebase, generic")
    topic: str = Field(..., description="e.g. authentication, rls, sql-injection, headers")
    category: str = Field("security-doc", description="Document category — always security-doc for our corpus")
    owasp: Optional[str] = Field(None, description="OWASP category e.g. A01, A03, A07")
    source: Optional[str] = Field(None, description="Where the doc came from e.g. official-docs, owasp, custom")

    def to_gemini_metadata(self) -> list[dict[str, Any]]:
        meta = [
            {"key": "framework", "string_value": self.framework},
            {"key": "topic",     "string_value": self.topic},
            {"key": "category",  "string_value": self.category},
        ]
        if self.owasp:
            meta.append({"key": "owasp", "string_value": self.owasp})
        if self.source:
            meta.append({"key": "source", "string_value": self.source})
        return meta


class UploadResponse(BaseModel):
    success: bool
    filename: str
    framework: str
    topic: str
    message: str
