from app import create_app

app = create_app()

if __name__ == '__main__':
    print("=" * 80)
    print("🚀 Cavista Hackathon 2026 API Server Starting...")
    print("=" * 80)
    print(f"📍 Server running on: http://localhost:5000")
    print(f"📚 API Documentation (Swagger): http://localhost:5000/apidocs")
    print(f"📄 OpenAPI Spec: http://localhost:5000/apispec_1.json")
    print("=" * 80)
    
    app.run(host='0.0.0.0', port=5000, debug=True)