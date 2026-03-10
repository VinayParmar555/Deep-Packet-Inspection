from pydantic import BaseModel


class DPIConfig(BaseModel):
    num_workers: int = 4
    queue_size: int = 10000
    verbose: bool = False