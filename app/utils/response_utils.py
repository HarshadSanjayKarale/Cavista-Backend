from flask import jsonify

def success_response(message, data=None, status_code=200):
    """
    Create a standardized success response.
    
    Args:
        message (str): Success message
        data (dict, optional): Response data payload
        status_code (int): HTTP status code (default: 200)
        
    Returns:
        tuple: (JSON response, status code)
        
    Example:
        return success_response("User created", {"user_id": "123"}, 201)
    """
    response = {
        "success": True,
        "message": message
    }
    if data is not None:
        response["data"] = data
    return jsonify(response), status_code

def error_response(message, status_code=400):
    """
    Create a standardized error response.
    
    Args:
        message (str): Error message
        status_code (int): HTTP status code (default: 400)
        
    Returns:
        tuple: (JSON response, status code)
        
    Example:
        return error_response("User not found", 404)
    """
    return jsonify({
        "success": False,
        "error": message
    }), status_code

def paginated_response(message, items, page, per_page, total, status_code=200):
    """
    Create a standardized paginated response.
    
    Args:
        message (str): Success message
        items (list): List of items for current page
        page (int): Current page number
        per_page (int): Items per page
        total (int): Total number of items
        status_code (int): HTTP status code (default: 200)
        
    Returns:
        tuple: (JSON response, status code)
        
    Example:
        return paginated_response(
            "Users retrieved",
            users_list,
            page=1,
            per_page=10,
            total=100
        )
    """
    total_pages = (total + per_page - 1) // per_page
    
    response = {
        "success": True,
        "message": message,
        "data": items,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_items": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }
    }
    return jsonify(response), status_code

def validation_error_response(errors):
    """
    Create a standardized validation error response.
    
    Args:
        errors (dict): Dictionary of field-level validation errors
        
    Returns:
        tuple: (JSON response, status code 422)
        
    Example:
        return validation_error_response({
            "email": "Invalid email format",
            "password": "Password too short"
        })
    """
    return jsonify({
        "success": False,
        "error": "Validation failed",
        "validation_errors": errors
    }), 422