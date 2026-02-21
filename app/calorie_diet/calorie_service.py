"""
calorie_service.py
Calorie calculation logic for detected food items
"""

# Portion to grams mapping
PORTION_TO_GRAMS = {
    "cup": 80,
    "bowl": 200,
    "plate": 350
}

# Nutrition database: calories per 100g
NUTRITION_DB = {
    "rice": 130,
    "chicken": 239,
    "beef": 250,
    "fish": 206,
    "egg": 155,
    "potato": 77,
    "tomato": 18,
    "carrot": 41,
    "apple": 52,
    "banana": 89,
    "bread": 265,
    "cheese": 402,
    "lettuce": 15,
    "beans": 127,
    "corn": 96,
    "pasta": 131,
    "broccoli": 34,
    "cucumber": 16,
    "orange": 47,
    "milk": 42
}


def calculate_calories(detected_items: list):
    """
    Calculate calories for detected food items.
    Returns processed_items list and total_calories.
    """
    processed_items = []
    total_calories = 0.0

    for item in detected_items:
        food_name = item.get("food_name")
        portion = item.get("portion")
        if food_name not in NUTRITION_DB or portion not in PORTION_TO_GRAMS:
            continue  # Skip unknown foods or portions
        grams = PORTION_TO_GRAMS[portion]
        calories_per_100g = NUTRITION_DB[food_name]
        calories = (grams / 100.0) * calories_per_100g
        processed_items.append({
            "food_name": food_name,
            "portion": portion,
            "grams": grams,
            "calories": round(calories, 2)
        })
        total_calories += calories

    return processed_items, round(total_calories, 2)
