# Google Fit Wearable Integration API Documentation

## Overview

This API provides Google Fit integration for retrieving health and fitness data including heart rate, steps, sleep, calories, weight, blood pressure, oxygen saturation, distance, speed, and activity tracking.

## Base URL

```
http://localhost:5000/api/wearable
```

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Google Cloud Console

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google Fit API:
   - Go to "APIs & Services" > "Library"
   - Search for "Fitness API"
   - Click "Enable"
4. Create OAuth 2.0 Credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Web application"
   - Add authorized redirect URIs:
     - `http://localhost:5000/api/wearable/auth/google/callback`
     - `http://127.0.0.1:5000/api/wearable/auth/google/callback`
   - Copy the Client ID and Client Secret

### 3. Configure Environment Variables

Create a `.env` file in the project root:

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
REDIRECT_URI=http://localhost:5000/api/wearable/auth/google/callback
FRONTEND_URL=http://localhost:3000
SECRET_KEY=your-secret-key
```

### 4. Start the Server

```bash
python run.py
```

## API Endpoints

### Authentication Endpoints

#### 1. Initiate Google OAuth

```
GET /api/wearable/auth/google
```

**Description:** Redirects user to Google OAuth consent screen

**Usage:**

- Visit this URL in browser: `http://localhost:5000/api/wearable/auth/google`
- Authorize the application
- You'll be redirected back with tokens stored in session

---

#### 2. OAuth Callback

```
GET /api/wearable/auth/google/callback
```

**Description:** Handles OAuth callback from Google (automatically called)

**Parameters:**

- `code` (query): Authorization code from Google

---

#### 3. Check Authentication Status

```
GET /api/wearable/auth/status
```

**Description:** Check if user is authenticated

**Response:**

```json
{
  "success": true,
  "authenticated": true
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/auth/status
```

---

#### 4. Logout

```
POST /api/wearable/auth/logout
```

**Description:** Clear authentication session

**Response:**

```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

**Example:**

```bash
curl -X POST http://localhost:5000/api/wearable/auth/logout
```

---

### Health Data Endpoints

> **Note:** All data endpoints require authentication. First authenticate via `/api/wearable/auth/google`

#### 5. Get Data Sources

```
GET /api/wearable/datasources
```

**Description:** List all available Google Fit data sources

**Response:**

```json
{
  "success": true,
  "data": {
    "dataSource": [
      {
        "dataType": {
          "name": "com.google.step_count.delta"
        }
      }
    ]
  }
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/datasources
```

---

#### 6. Get Heart Rate Data

```
GET /api/wearable/heartrate
```

**Description:** Retrieve heart rate data from last 24 hours

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "timestamp": 1708524000000,
      "average": 72.5,
      "min": 65.0,
      "max": 85.0
    }
  ],
  "count": 24
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/heartrate
```

---

#### 7. Get Steps Data

```
GET /api/wearable/steps
```

**Description:** Retrieve daily step count for last 7 days

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "steps": 8540
    },
    {
      "date": "2026-02-16",
      "steps": 10234
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/steps
```

---

#### 8. Get Activity Data

```
GET /api/wearable/activity
```

**Description:** Retrieve activity segments from last 24 hours

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "type": "Walking",
      "startTime": 1708524000000,
      "endTime": 1708527600000,
      "duration": 3600
    },
    {
      "type": "Running",
      "startTime": 1708531200000,
      "endTime": 1708532800000,
      "duration": 1600
    }
  ],
  "count": 12
}
```

**Activity Types:**

- 1: Biking
- 7: Walking
- 8: Running
- 9: Aerobics
- 72: Sleeping

**Example:**

```bash
curl http://localhost:5000/api/wearable/activity
```

---

#### 9. Get Sleep Data

```
GET /api/wearable/sleep
```

**Description:** Retrieve daily sleep hours for last 7 days

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "sleepHours": 7.5
    },
    {
      "date": "2026-02-16",
      "sleepHours": 8.2
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/sleep
```

---

#### 10. Get Calories Data

```
GET /api/wearable/calories
```

**Description:** Retrieve daily calories burned for last 7 days

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "calories": 2450
    },
    {
      "date": "2026-02-16",
      "calories": 2680
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/calories
```

---

#### 11. Get Weight Data

```
GET /api/wearable/weight
```

**Description:** Retrieve daily weight and BMI for last 7 days

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "weight": "75.5",
      "bmi": "24.2"
    },
    {
      "date": "2026-02-16",
      "weight": "75.3",
      "bmi": "24.1"
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/weight
```

---

#### 12. Get Blood Pressure Data

```
GET /api/wearable/bloodpressure
```

**Description:** Retrieve blood pressure readings for last 7 days

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "timestamp": 1708524000000,
      "date": "02/15/2026",
      "systolic": 120.0,
      "diastolic": 80.0
    },
    {
      "timestamp": 1708610400000,
      "date": "02/16/2026",
      "systolic": 118.0,
      "diastolic": 78.0
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/bloodpressure
```

---

#### 13. Get Oxygen Saturation Data

```
GET /api/wearable/oxygen
```

**Description:** Retrieve oxygen saturation (SpO2) for last 7 days

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "oxygen": "98.5"
    },
    {
      "date": "2026-02-16",
      "oxygen": "97.8"
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/oxygen
```

---

#### 14. Get Distance Data

```
GET /api/wearable/distance
```

**Description:** Retrieve daily distance traveled for last 7 days (in meters)

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "distance": 5420
    },
    {
      "date": "2026-02-16",
      "distance": 6780
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/distance
```

---

#### 15. Get Speed Data

```
GET /api/wearable/speed
```

**Description:** Retrieve average speed for last 7 days (in m/s)

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "date": "2026-02-15",
      "speed": "1.25"
    },
    {
      "date": "2026-02-16",
      "speed": "1.45"
    }
  ],
  "count": 7
}
```

**Example:**

```bash
curl http://localhost:5000/api/wearable/speed
```

---

## Testing Workflow

### 1. Using Browser (Recommended for OAuth)

1. **Start the server:**

   ```bash
   python run.py
   ```

2. **Authenticate:**
   - Open browser: `http://localhost:5000/api/wearable/auth/google`
   - Sign in with Google account
   - Grant permissions
   - You'll be redirected to frontend

3. **Test endpoints in browser or Postman:**
   - `http://localhost:5000/api/wearable/auth/status`
   - `http://localhost:5000/api/wearable/steps`
   - `http://localhost:5000/api/wearable/heartrate`
   - etc.

### 2. Using Postman

1. **Import Collection:**
   - Create new collection "Google Fit API"
   - Add all endpoints listed above

2. **Authenticate:**
   - Open browser: `http://localhost:5000/api/wearable/auth/google`
   - Complete OAuth flow

3. **Test endpoints:**
   - Session cookies are automatically managed
   - Test any data endpoint

### 3. Swagger Documentation

Visit `http://localhost:5000/apidocs` to see interactive API documentation with "Try it out" buttons.

---

## Error Responses

### Not Authenticated

```json
{
  "success": false,
  "error": "Not authenticated with Google Fit",
  "message": "Please authenticate first via /api/wearable/auth/google"
}
```

### Token Expired

```json
{
  "success": false,
  "error": "Token refresh failed",
  "message": "Please re-authenticate via /api/wearable/auth/google"
}
```

### Data Fetch Failed

```json
{
  "success": false,
  "error": "Failed to fetch data",
  "data": []
}
```

---

## Important Notes

1. **Session Management:**
   - Sessions are stored in filesystem
   - Session data includes OAuth tokens
   - Sessions expire after 24 hours

2. **Token Refresh:**
   - Access tokens are automatically refreshed
   - Refresh tokens are stored in session
   - Re-authentication required if refresh fails

3. **Data Availability:**
   - Data depends on user's Google Fit account
   - Some data may be empty if not tracked
   - Different devices provide different data types

4. **CORS:**
   - Configured to support frontend integration
   - Credentials are supported for session cookies

5. **Testing with Mock Data:**
   - If no real Google Fit data, endpoints return empty arrays
   - Use Google Fit mobile app to generate test data

---

## Troubleshooting

### Issue: "Not authenticated" error

**Solution:** Visit `/api/wearable/auth/google` in browser first

### Issue: "Token refresh failed"

**Solution:** Re-authenticate via `/api/wearable/auth/google`

### Issue: Empty data arrays

**Solution:**

- Ensure Google Fit has data for your account
- Check that correct scopes are authorized
- Use Google Fit app to generate test data

### Issue: OAuth redirect fails

**Solution:**

- Verify redirect URI in Google Cloud Console
- Check REDIRECT_URI in .env matches console setting
- Ensure no typos in callback URL

---

## Complete Testing Script

```bash
# 1. Start server
python run.py

# 2. Authenticate (open in browser)
# http://localhost:5000/api/wearable/auth/google

# 3. Test authentication status
curl http://localhost:5000/api/wearable/auth/status

# 4. Test data endpoints
curl http://localhost:5000/api/wearable/steps
curl http://localhost:5000/api/wearable/heartrate
curl http://localhost:5000/api/wearable/sleep
curl http://localhost:5000/api/wearable/calories
curl http://localhost:5000/api/wearable/activity

# 5. Logout
curl -X POST http://localhost:5000/api/wearable/auth/logout
```

---

## Integration with Existing API

The wearable endpoints are now integrated into your main API at `/api/wearable`. Visit:

```
http://localhost:5000/
```

To see all available endpoints including the new wearable integration.

---

## Next Steps

1. Configure Google Cloud Console with OAuth credentials
2. Add credentials to `.env` file
3. Install new dependencies: `pip install flask-session`
4. Test authentication flow
5. Test data endpoints
6. Integrate with frontend application

---

## Support

For issues or questions:

- Check Swagger docs: `http://localhost:5000/apidocs`
- Review Google Fit API documentation
- Check console logs for detailed error messages
