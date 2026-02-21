# 🚀 Cavista Hackathon 2026 API

A production-ready Flask RESTful API with JWT authentication and comprehensive Swagger/OpenAPI documentation.

## ✨ Features

- ✅ **User Authentication** - Register, Login, Logout
- ✅ **JWT Token-based Security** - Secure API endpoints
- ✅ **Password Management** - Change password functionality
- ✅ **Profile Management** - Update user profiles
- ✅ **MongoDB Integration** - NoSQL database support
- ✅ **CORS Enabled** - Cross-origin resource sharing
- ✅ **Swagger/OpenAPI Documentation** - Interactive API docs
- ✅ **Role-based Access Control** - Admin, User, Moderator roles
- ✅ **Production-ready** - Error handling, validation, and logging

## 📋 Prerequisites

- Python 3.8 or higher
- MongoDB 4.4 or higher
- pip (Python package manager)

## 🛠️ Installation

### 1. Clone or Navigate to Project Directory

```bash
cd "c:\Users\ADMIN\Desktop\Projects\Cavista Hackathon 2026"
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv venv
.\venv\Scripts\Activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the root directory (already provided):

```env
SECRET_KEY=cavista-hackathon-super-secret-key-2026-change-in-production
JWT_SECRET_KEY=cavista-jwt-super-secret-2026-change-in-production
MONGO_URI=mongodb://localhost:27017/cavista_hackathon
JWT_EXPIRATION_HOURS=24
DEBUG=True
```

**⚠️ Important:** Change the secret keys in production!

### 5. Start MongoDB

**Windows:**
```bash
net start MongoDB
```

**Mac:**
```bash
brew services start mongodb-community
```

**Linux:**
```bash
sudo systemctl start mongod
```

### 6. Run the Application

```bash
python run.py
```

The API will be available at:
- **API Base URL:** `http://localhost:5000`
- **Swagger Documentation:** `http://localhost:5000/apidocs`
- **OpenAPI Spec:** `http://localhost:5000/apispec_1.json`

## 📚 API Documentation

### Interactive Documentation

Open your browser and navigate to:
```
http://localhost:5000/apidocs
```

This provides an interactive Swagger UI where you can:
- View all available endpoints
- Test API calls directly
- See request/response schemas
- Copy example requests

## 🔐 API Endpoints

### Authentication Endpoints

#### 1. Register User
```http
POST /api/auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123",
    "full_name": "John Doe",
    "role": "user",
    "phone": "+1234567890"
}
```

**Response (201):**
```json
{
    "success": true,
    "message": "User registered successfully",
    "data": {
        "user_id": "507f1f77bcf86cd799439011",
        "email": "user@example.com",
        "full_name": "John Doe"
    }
}
```

#### 2. Login
```http
POST /api/auth/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123"
}
```

**Response (200):**
```json
{
    "success": true,
    "message": "Login successful",
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "user": {
            "id": "507f1f77bcf86cd799439011",
            "email": "user@example.com",
            "full_name": "John Doe",
            "role": "user",
            "phone": "+1234567890",
            "is_verified": false
        }
    }
}
```

### Protected Endpoints (Require Authentication)

For all protected endpoints, include the JWT token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 3. Get Profile
```http
GET /api/auth/profile
Authorization: Bearer <your-token>
```

#### 4. Update Profile
```http
PUT /api/auth/profile
Authorization: Bearer <your-token>
Content-Type: application/json

{
    "full_name": "Jane Doe",
    "phone": "+9876543210"
}
```

#### 5. Change Password
```http
PUT /api/auth/change-password
Authorization: Bearer <your-token>
Content-Type: application/json

{
    "old_password": "OldPass123",
    "new_password": "NewSecurePass123"
}
```

#### 6. Verify Token
```http
GET /api/auth/verify-token
Authorization: Bearer <your-token>
```

#### 7. Logout
```http
POST /api/auth/logout
Authorization: Bearer <your-token>
```

## 🧪 Testing with Postman/Thunder Client

### Step-by-Step Testing Guide

1. **Health Check**
   - Method: `GET`
   - URL: `http://localhost:5000/`
   - No authentication required

2. **Register a User**
   - Method: `POST`
   - URL: `http://localhost:5000/api/auth/register`
   - Body: JSON (see Register endpoint above)

3. **Login**
   - Method: `POST`
   - URL: `http://localhost:5000/api/auth/login`
   - Body: JSON (see Login endpoint above)
   - **Save the token from response!**

4. **Access Protected Endpoints**
   - Add token to Authorization header:
   - Header Key: `Authorization`
   - Header Value: `Bearer <your-token-here>`

### Postman Collection

Import this collection to Postman:

```json
{
    "info": {
        "name": "Cavista Hackathon 2026 API",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    "item": [
        {
            "name": "Auth",
            "item": [
                {
                    "name": "Register",
                    "request": {
                        "method": "POST",
                        "header": [],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n    \"email\": \"user@example.com\",\n    \"password\": \"SecurePass123\",\n    \"full_name\": \"John Doe\"\n}",
                            "options": {
                                "raw": {
                                    "language": "json"
                                }
                            }
                        },
                        "url": {
                            "raw": "http://localhost:5000/api/auth/register",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5000",
                            "path": ["api", "auth", "register"]
                        }
                    }
                },
                {
                    "name": "Login",
                    "request": {
                        "method": "POST",
                        "header": [],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n    \"email\": \"user@example.com\",\n    \"password\": \"SecurePass123\"\n}",
                            "options": {
                                "raw": {
                                    "language": "json"
                                }
                            }
                        },
                        "url": {
                            "raw": "http://localhost:5000/api/auth/login",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5000",
                            "path": ["api", "auth", "login"]
                        }
                    }
                }
            ]
        }
    ]
}
```

## 📁 Project Structure

```
Cavista Hackathon 2026/
├── app/
│   ├── __init__.py              # Application factory with Swagger setup
│   ├── config.py                # Configuration management
│   ├── extensions.py            # Flask extensions (MongoDB)
│   ├── models/
│   │   └── user_model.py        # User data model
│   ├── routes/
│   │   ├── __init__.py
│   │   └── auth_routes.py       # Authentication routes with Swagger docs
│   └── utils/
│       ├── __init__.py
│       ├── auth_utils.py        # JWT decorators and helpers
│       └── response_utils.py    # Response formatting utilities
├── .env                          # Environment variables
├── .gitignore                    # Git ignore file
├── README.md                     # This file
├── requirements.txt              # Python dependencies
└── run.py                        # Application entry point
```

## 🔒 Security Features

- **Password Hashing:** bcrypt with salt
- **JWT Tokens:** Secure token-based authentication
- **Token Expiration:** Configurable expiration time
- **Role-based Access:** Admin, User, Moderator roles
- **Input Validation:** Request data validation
- **CORS Protection:** Configurable CORS policies
- **Environment Variables:** Sensitive data in .env

## 🚀 Extending the API

### Adding New Routes

1. Create a new blueprint in `app/routes/`:

```python
# filepath: app/routes/your_routes.py
from flask import Blueprint
from app.utils.auth_utils import token_required

your_bp = Blueprint('your_feature', __name__)

@your_bp.route('/your-endpoint', methods=['GET'])
@token_required
def your_endpoint(current_user):
    """
    Your Endpoint
    ---
    tags:
      - Your Feature
    security:
      - Bearer: []
    responses:
      200:
        description: Success
    """
    return {"message": "Hello from your endpoint"}
```

2. Register blueprint in `app/__init__.py`:

```python
from app.routes.your_routes import your_bp
app.register_blueprint(your_bp, url_prefix='/api/your')
```

### Adding New Models

1. Create model in `app/models/`:

```python
# filepath: app/models/your_model.py
from datetime import datetime

class YourModel:
    def __init__(self, field1, field2):
        self.field1 = field1
        self.field2 = field2
        self.created_at = datetime.utcnow()
    
    def to_dict(self):
        return {
            "field1": self.field1,
            "field2": self.field2,
            "created_at": self.created_at
        }
```

## 🐛 Troubleshooting

### MongoDB Connection Issues

```bash
# Check if MongoDB is running
# Windows
sc query MongoDB

# Mac/Linux
systemctl status mongod
```

### Port Already in Use

```bash
# Find process using port 5000
# Windows
netstat -ano | findstr :5000

# Mac/Linux
lsof -i :5000

# Kill the process
# Windows
taskkill /PID <PID> /F

# Mac/Linux
kill -9 <PID>
```

### Import Errors

```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

## 📝 License

MIT License - Cavista Hackathon 2026

## 👥 Contributors

- Your Team Name
- Team Members

## 🎯 Next Steps

1. ✅ Test all authentication endpoints
2. ✅ Explore Swagger documentation
3. ⬜ Add custom business logic
4. ⬜ Implement additional features
5. ⬜ Deploy to production

## 📧 Support

For issues or questions, please create an issue in the project repository.

---

**Happy Hacking! 🚀**

*Built with ❤️ for Cavista Hackathon 2026*
```

This complete implementation provides:

1. ✅ **Full authentication system** with JWT
2. ✅ **Comprehensive Swagger/OpenAPI documentation**
3. ✅ **Interactive API testing** via Swagger UI
4. ✅ **Production-ready code** with error handling
5. ✅ **Complete project structure**
6. ✅ **Detailed README** with examples
7. ✅ **Security best practices**
8. ✅ **Easy to extend** for your hackathon project

Access Swagger documentation at: `http://localhost:5000/apidocs`# filepath: c:\Users\ADMIN\Desktop\Projects\Cavista Hackathon 2026\README.md
# 🚀 Cavista Hackathon 2026 API

A production-ready Flask RESTful API with JWT authentication and comprehensive Swagger/OpenAPI documentation.

## ✨ Features

- ✅ **User Authentication** - Register, Login, Logout
- ✅ **JWT Token-based Security** - Secure API endpoints
- ✅ **Password Management** - Change password functionality
- ✅ **Profile Management** - Update user profiles
- ✅ **MongoDB Integration** - NoSQL database support
- ✅ **CORS Enabled** - Cross-origin resource sharing
- ✅ **Swagger/OpenAPI Documentation** - Interactive API docs
- ✅ **Role-based Access Control** - Admin, User, Moderator roles
- ✅ **Production-ready** - Error handling, validation, and logging

## 📋 Prerequisites

- Python 3.8 or higher
- MongoDB 4.4 or higher
- pip (Python package manager)

## 🛠️ Installation

### 1. Clone or Navigate to Project Directory

```bash
cd "c:\Users\ADMIN\Desktop\Projects\Cavista Hackathon 2026"
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv venv
.\venv\Scripts\Activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the root directory (already provided):

```env
SECRET_KEY=cavista-hackathon-super-secret-key-2026-change-in-production
JWT_SECRET_KEY=cavista-jwt-super-secret-2026-change-in-production
MONGO_URI=mongodb://localhost:27017/cavista_hackathon
JWT_EXPIRATION_HOURS=24
DEBUG=True
```

**⚠️ Important:** Change the secret keys in production!

### 5. Start MongoDB

**Windows:**
```bash
net start MongoDB
```

**Mac:**
```bash
brew services start mongodb-community
```

**Linux:**
```bash
sudo systemctl start mongod
```

### 6. Run the Application

```bash
python run.py
```

The API will be available at:
- **API Base URL:** `http://localhost:5000`
- **Swagger Documentation:** `http://localhost:5000/apidocs`
- **OpenAPI Spec:** `http://localhost:5000/apispec_1.json`

## 📚 API Documentation

### Interactive Documentation

Open your browser and navigate to:
```
http://localhost:5000/apidocs
```

This provides an interactive Swagger UI where you can:
- View all available endpoints
- Test API calls directly
- See request/response schemas
- Copy example requests

## 🔐 API Endpoints

### Authentication Endpoints

#### 1. Register User
```http
POST /api/auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123",
    "full_name": "John Doe",
    "role": "user",
    "phone": "+1234567890"
}
```

**Response (201):**
```json
{
    "success": true,
    "message": "User registered successfully",
    "data": {
        "user_id": "507f1f77bcf86cd799439011",
        "email": "user@example.com",
        "full_name": "John Doe"
    }
}
```

#### 2. Login
```http
POST /api/auth/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePass123"
}
```

**Response (200):**
```json
{
    "success": true,
    "message": "Login successful",
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "user": {
            "id": "507f1f77bcf86cd799439011",
            "email": "user@example.com",
            "full_name": "John Doe",
            "role": "user",
            "phone": "+1234567890",
            "is_verified": false
        }
    }
}
```

### Protected Endpoints (Require Authentication)

For all protected endpoints, include the JWT token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 3. Get Profile
```http
GET /api/auth/profile
Authorization: Bearer <your-token>
```

#### 4. Update Profile
```http
PUT /api/auth/profile
Authorization: Bearer <your-token>
Content-Type: application/json

{
    "full_name": "Jane Doe",
    "phone": "+9876543210"
}
```

#### 5. Change Password
```http
PUT /api/auth/change-password
Authorization: Bearer <your-token>
Content-Type: application/json

{
    "old_password": "OldPass123",
    "new_password": "NewSecurePass123"
}
```

#### 6. Verify Token
```http
GET /api/auth/verify-token
Authorization: Bearer <your-token>
```

#### 7. Logout
```http
POST /api/auth/logout
Authorization: Bearer <your-token>
```

## 🧪 Testing with Postman/Thunder Client

### Step-by-Step Testing Guide

1. **Health Check**
   - Method: `GET`
   - URL: `http://localhost:5000/`
   - No authentication required

2. **Register a User**
   - Method: `POST`
   - URL: `http://localhost:5000/api/auth/register`
   - Body: JSON (see Register endpoint above)

3. **Login**
   - Method: `POST`
   - URL: `http://localhost:5000/api/auth/login`
   - Body: JSON (see Login endpoint above)
   - **Save the token from response!**

4. **Access Protected Endpoints**
   - Add token to Authorization header:
   - Header Key: `Authorization`
   - Header Value: `Bearer <your-token-here>`

### Postman Collection

Import this collection to Postman:

```json
{
    "info": {
        "name": "Cavista Hackathon 2026 API",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    "item": [
        {
            "name": "Auth",
            "item": [
                {
                    "name": "Register",
                    "request": {
                        "method": "POST",
                        "header": [],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n    \"email\": \"user@example.com\",\n    \"password\": \"SecurePass123\",\n    \"full_name\": \"John Doe\"\n}",
                            "options": {
                                "raw": {
                                    "language": "json"
                                }
                            }
                        },
                        "url": {
                            "raw": "http://localhost:5000/api/auth/register",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5000",
                            "path": ["api", "auth", "register"]
                        }
                    }
                },
                {
                    "name": "Login",
                    "request": {
                        "method": "POST",
                        "header": [],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n    \"email\": \"user@example.com\",\n    \"password\": \"SecurePass123\"\n}",
                            "options": {
                                "raw": {
                                    "language": "json"
                                }
                            }
                        },
                        "url": {
                            "raw": "http://localhost:5000/api/auth/login",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5000",
                            "path": ["api", "auth", "login"]
                        }
                    }
                }
            ]
        }
    ]
}
```

## 📁 Project Structure

```
Cavista Hackathon 2026/
├── app/
│   ├── __init__.py              # Application factory with Swagger setup
│   ├── config.py                # Configuration management
│   ├── extensions.py            # Flask extensions (MongoDB)
│   ├── models/
│   │   └── user_model.py        # User data model
│   ├── routes/
│   │   ├── __init__.py
│   │   └── auth_routes.py       # Authentication routes with Swagger docs
│   └── utils/
│       ├── __init__.py
│       ├── auth_utils.py        # JWT decorators and helpers
│       └── response_utils.py    # Response formatting utilities
├── .env                          # Environment variables
├── .gitignore                    # Git ignore file
├── README.md                     # This file
├── requirements.txt              # Python dependencies
└── run.py                        # Application entry point
```

## 🔒 Security Features

- **Password Hashing:** bcrypt with salt
- **JWT Tokens:** Secure token-based authentication
- **Token Expiration:** Configurable expiration time
- **Role-based Access:** Admin, User, Moderator roles
- **Input Validation:** Request data validation
- **CORS Protection:** Configurable CORS policies
- **Environment Variables:** Sensitive data in .env

## 🚀 Extending the API

### Adding New Routes

1. Create a new blueprint in `app/routes/`:

```python
# filepath: app/routes/your_routes.py
from flask import Blueprint
from app.utils.auth_utils import token_required

your_bp = Blueprint('your_feature', __name__)

@your_bp.route('/your-endpoint', methods=['GET'])
@token_required
def your_endpoint(current_user):
    """
    Your Endpoint
    ---
    tags:
      - Your Feature
    security:
      - Bearer: []
    responses:
      200:
        description: Success
    """
    return {"message": "Hello from your endpoint"}
```

2. Register blueprint in `app/__init__.py`:

```python
from app.routes.your_routes import your_bp
app.register_blueprint(your_bp, url_prefix='/api/your')
```

### Adding New Models

1. Create model in `app/models/`:

```python
# filepath: app/models/your_model.py
from datetime import datetime

class YourModel:
    def __init__(self, field1, field2):
        self.field1 = field1
        self.field2 = field2
        self.created_at = datetime.utcnow()
    
    def to_dict(self):
        return {
            "field1": self.field1,
            "field2": self.field2,
            "created_at": self.created_at
        }
```

## 🐛 Troubleshooting

### MongoDB Connection Issues

```bash
# Check if MongoDB is running
# Windows
sc query MongoDB

# Mac/Linux
systemctl status mongod
```

### Port Already in Use

```bash
# Find process using port 5000
# Windows
netstat -ano | findstr :5000

# Mac/Linux
lsof -i :5000

# Kill the process
# Windows
taskkill /PID <PID> /F

# Mac/Linux
kill -9 <PID>
```

### Import Errors

```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

## 📝 License

MIT License - Cavista Hackathon 2026

## 👥 Contributors

- Your Team Name
- Team Members

## 🎯 Next Steps

1. ✅ Test all authentication endpoints
2. ✅ Explore Swagger documentation
3. ⬜ Add custom business logic
4. ⬜ Implement additional features
5. ⬜ Deploy to production

## 📧 Support

For issues or questions, please create an issue in the project repository.

---

**Happy Hacking! 🚀**

*Built with ❤️ for Cavista Hackathon 2026*
```

This complete implementation provides:

1. ✅ **Full authentication system** with JWT
2. ✅ **Comprehensive Swagger/OpenAPI documentation**
3. ✅ **Interactive API testing** via Swagger UI
4. ✅ **Production-ready code** with error handling
5. ✅ **Complete project structure**
6. ✅ **Detailed README** with examples
7. ✅ **Security best practices**
8. ✅ **Easy to extend** for your hackathon project

Access Swagger documentation at: `http://localhost:5000/apidocs`