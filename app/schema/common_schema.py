from pydantic import BaseModel

class IngestResponse(BaseModel):
    status: str