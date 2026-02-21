"""
Background scheduler for mock data generation
"""
import threading
import time
from app.routes.wearable.mock_data_generator import MockWearableDataGenerator

class MockDataScheduler:
    def __init__(self):
        self.active_users = {}
        self.running = False
        self.thread = None
    
    def add_user(self, user_id):
        """Add user to active generation"""
        if user_id not in self.active_users:
            self.active_users[user_id] = MockWearableDataGenerator(user_id)
    
    def remove_user(self, user_id):
        """Remove user from active generation"""
        if user_id in self.active_users:
            del self.active_users[user_id]
    
    def _generate_loop(self):
        """Background loop to generate data every minute"""
        while self.running:
            for user_id, generator in self.active_users.items():
                try:
                    generator.save_data_point()
                    print(f"✅ Generated data for user {user_id}")
                except Exception as e:
                    print(f"❌ Error generating data for {user_id}: {e}")
            
            time.sleep(60)  # Wait 1 minute
    
    def start(self):
        """Start the scheduler"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._generate_loop, daemon=True)
            self.thread.start()
            print("🚀 Mock data scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.thread:
            self.thread.join()
        print("⏹️  Mock data scheduler stopped")

# Global scheduler instance
scheduler = MockDataScheduler()