"""
process_meal_router.py
FastAPI router for meal processing
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from bson import ObjectId
from datetime import datetime
from app.diet_image_processor.detection_service import fetch_image_from_url, detect_food_items
from app.diet_image_processor.calorie_service import calculate_calories
from app.config import get_database

router = APIRouter()

db = get_database()
meals_collection = db["meals"]
calc_count_collection = db["calc_count"]

class UploadMealRequest(BaseModel):
    image_url: str
    patient_id: str

class ProcessMealRequest(BaseModel):
    meal_id: str

@router.post("/upload-meal")
def upload_meal(request: UploadMealRequest):
    if not request.image_url or not request.patient_id:
        raise HTTPException(status_code=400, detail="image_url and patient_id required")
    meal_doc = {
        "image_url": request.image_url,
        "user_id": request.patient_id,
        "uploaded_at": datetime.utcnow()
    }
    try:
        result = meals_collection.insert_one(meal_doc)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload meal: {e}")
    return {
        "status": "uploaded",
        "meal_id": str(result.inserted_id)
    }

@router.post("/process-meal")
def process_meal(request: ProcessMealRequest):
    try:
        meal_obj_id = ObjectId(request.meal_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid meal_id")
    meal_doc = meals_collection.find_one({"_id": meal_obj_id})
    if not meal_doc:
        raise HTTPException(status_code=404, detail="Meal not found")
    image_url = meal_doc.get("image_url")
    user_id = meal_doc.get("user_id")
    if not image_url or not user_id:
        raise HTTPException(status_code=400, detail="Meal document missing image_url or user_id")
    try:
        image = fetch_image_from_url(image_url)
        detected_items = detect_food_items(image)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image processing failed: {e}")
    try:
        processed_items, total_calories = calculate_calories(detected_items)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Calorie calculation failed: {e}")
    result_doc = {
        "meal_id": meal_obj_id,
        "user_id": user_id,
        "detected_items": processed_items,
        "total_calories": total_calories,
        "processed_at": datetime.utcnow()
    }
    try:
        calc_count_collection.insert_one(result_doc)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save result: {e}")
    return {
        "status": "processed",
        "total_calories": total_calories,
        "items": processed_items
    }

@router.get("/meal/{meal_id}")
def get_meal(meal_id: str):
    try:
        meal_obj_id = ObjectId(meal_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid meal_id")
    meal_doc = meals_collection.find_one({"_id": meal_obj_id})
    if not meal_doc:
        raise HTTPException(status_code=404, detail="Meal not found")
    calc_doc = calc_count_collection.find_one({"meal_id": meal_obj_id})
    return {
        "meal_id": meal_id,
        "image_url": meal_doc.get("image_url"),
        "user_id": meal_doc.get("user_id"),
        "uploaded_at": meal_doc.get("uploaded_at"),
        "calories": calc_doc.get("total_calories") if calc_doc else None,
        "items": calc_doc.get("detected_items") if calc_doc else [],
        "processed_at": calc_doc.get("processed_at") if calc_doc else None
    }

@router.get("/meals/search")
def search_meals(
    patient_id: str = Query(None),
    min_calories: float = Query(None),
    max_calories: float = Query(None),
    date_from: datetime = Query(None),
    date_to: datetime = Query(None)
):
    query = {}
    if patient_id:
        query["user_id"] = patient_id
    if min_calories is not None or max_calories is not None:
        calorie_query = {}
        if min_calories is not None:
            calorie_query["$gte"] = min_calories
        if max_calories is not None:
            calorie_query["$lte"] = max_calories
        query["total_calories"] = calorie_query
    if date_from or date_to:
        date_query = {}
        if date_from:
            date_query["$gte"] = date_from
        if date_to:
            date_query["$lte"] = date_to
        query["processed_at"] = date_query
    meals = list(calc_count_collection.find(query).limit(50))
    for meal in meals:
        meal["meal_id"] = str(meal["meal_id"])
        meal["_id"] = str(meal["_id"])
    return {
        "count": len(meals),
        "meals": meals
    }
