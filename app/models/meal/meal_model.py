from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class MealModel(BaseModel):
    image_url: str
    user_id: str
    uploaded_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    # MongoDB system fields
    _id: Optional[str] = None

    class Config:
        orm_mode = True
        allow_population_by_field_name = True
