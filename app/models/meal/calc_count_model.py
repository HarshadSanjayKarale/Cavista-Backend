from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

class DetectedItemModel(BaseModel):
    food_name: str
    portion: str
    grams: int
    calories: float

class CalcCountModel(BaseModel):
    meal_id: str
    user_id: str
    detected_items: List[DetectedItemModel]
    total_calories: float
    processed_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    # MongoDB system fields
    _id: Optional[str] = None

    class Config:
        orm_mode = True
        allow_population_by_field_name = True
