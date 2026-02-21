"""
detection_service.py
Food detection using YOLOv8 (ultralytics)
"""

import requests
from PIL import Image
from io import BytesIO
from ultralytics import YOLO

# Load YOLOv8 model globally
YOLO_MODEL_PATH = "yolov8n.pt"
model = YOLO(YOLO_MODEL_PATH)


def fetch_image_from_url(image_url: str, timeout: int = 10) -> Image.Image:
    """
    Fetch image from URL and return PIL Image.
    Raises exception on failure.
    """
    try:
        response = requests.get(image_url, timeout=timeout)
        response.raise_for_status()
        image = Image.open(BytesIO(response.content)).convert("RGB")
        return image
    except Exception as e:
        raise RuntimeError(f"Failed to fetch image: {e}")


def detect_food_items(image: Image.Image) -> list:
    """
    Run YOLOv8 detection on image.
    Returns list of detected food items with portion and area ratio.
    """
    results = model(image)
    image_area = image.width * image.height
    detected_items = []

    for r in results:
        for box in r.boxes:
            cls_id = int(box.cls[0].item())
            food_name = r.names[cls_id]
            confidence = float(box.conf[0].item())
            # Bounding box coordinates
            x1, y1, x2, y2 = [float(coord.item()) for coord in box.xyxy[0]]
            box_area = (x2 - x1) * (y2 - y1)
            area_ratio = box_area / image_area
            # Portion assignment
            if area_ratio < 0.05:
                portion = "cup"
            elif area_ratio < 0.15:
                portion = "bowl"
            else:
                portion = "plate"
            detected_items.append({
                "food_name": food_name,
                "confidence": confidence,
                "portion": portion,
                "area_ratio": area_ratio
            })
    return detected_items
