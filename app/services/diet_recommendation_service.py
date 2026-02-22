"""
Diet Recommendation Service
Generates personalized diet plans based on risk assessment data using Gemini AI
"""
import os
import time
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv

load_dotenv()

class DietRecommendationAgent:
    """Agent for generating personalized diet recommendations"""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash-exp",
            google_api_key=os.getenv('GEMINI_API_KEY'),
            temperature=0.4,
            convert_system_message_to_human=True,
            max_retries=3
        )
        
        self.prompt_template = """You are an expert nutritionist and dietitian creating personalized diet plans.

**PATIENT ID:** {user_id}
**ASSESSMENT DATE:** {assessment_date}

**HEALTH METRICS:**
{health_metrics}

**RISK ASSESSMENT:**
- Risk Class: {risk_class}
- Risk Probability: {risk_probability}%
- Cardiac Risk Score: {cardiac_csr}
- Diabetic Risk Score: {diabetic_csr}

**TOP RISK FACTORS:**
{risk_factors}

**YOUR TASK:**
Create a personalized daily diet plan in the following EXACT format:

Time | Meal | Food
Morning | Empty Stomach | [Your recommendation]
Breakfast | Main Meal | [Your recommendation]
Mid-Morning | Snack | [Your recommendation]
Lunch | Main Meal | [Your recommendation]
Evening | Snack | [Your recommendation]
Dinner | Main Meal | [Your recommendation]
Night | Optional | [Your recommendation]

**GUIDELINES:**
1. Consider the patient's BMI ({bmi}), activity level ({active_min} minutes), and health scores
2. Address specific risk factors (cardiac risk: {cardiac_csr}, diabetic risk: {diabetic_csr})
3. Provide portion sizes and preparation methods
4. Keep meals simple, practical, and culturally appropriate (Indian/South Asian cuisine preferred)
5. Focus on heart health if cardiac risk is high
6. Focus on low GI foods if diabetic risk is high
7. Ensure adequate protein, fiber, and micronutrients
8. Limit processed foods, excess salt, and refined sugars

**ADDITIONAL RECOMMENDATIONS:**
After the table, provide 3-5 bullet points with:
- Daily water intake goal
- Foods to avoid
- Meal timing tips
- Any supplements if needed

Generate the personalized diet plan now in the EXACT table format shown above:"""

    def generate_diet_plan(self, user_id: str, risk_assessment_data: dict, assessment_date: str) -> dict:
        """
        Generate personalized diet plan based on risk assessment
        
        Args:
            user_id: Patient identifier
            risk_assessment_data: Risk assessment output from ML model
            assessment_date: Date of assessment
            
        Returns:
            Dictionary with structured diet plan
        """
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                # Extract data
                risk_assessment = risk_assessment_data.get('risk_assessment', {})
                health_metrics = risk_assessment_data.get('health_metrics', {})
                derived_scores = risk_assessment_data.get('derived_scores', {})
                risk_factors = risk_assessment_data.get('risk_factors', {})
                
                # Format risk factors
                top_factors = risk_factors.get('top_contributing_factors', [])[:5]
                factors_text = "\n".join([
                    f"- {f.get('feature', 'Unknown')}: {f.get('contribution', 0):+.4f} ({f.get('impact', 'Unknown')})"
                    for f in top_factors
                ])
                
                # Format health metrics
                metrics_text = f"""
- Daily Steps: {health_metrics.get('steps', 0):,}
- BMI: {health_metrics.get('bmi', 0):.1f}
- Sleep: {health_metrics.get('sleep_hrs', 0)} hours
- Active Minutes: {health_metrics.get('active_min', 0)} min
- Resting Heart Rate: {health_metrics.get('heart_rate', 0)} bpm
- Calories Burned: {health_metrics.get('calories', 0):,}
"""
                
                # Create prompt
                prompt = self.prompt_template.format(
                    user_id=user_id,
                    assessment_date=assessment_date,
                    health_metrics=metrics_text,
                    risk_class=risk_assessment.get('risk_class', 'N/A'),
                    risk_probability=f"{risk_assessment.get('risk_percentage', 0):.2f}",
                    cardiac_csr=f"{derived_scores.get('cardiac_csr', 0):.2f}",
                    diabetic_csr=f"{derived_scores.get('diabetic_csr', 0):.2f}",
                    risk_factors=factors_text,
                    bmi=health_metrics.get('bmi', 0),
                    active_min=health_metrics.get('active_min', 0)
                )
                
                # Generate diet plan
                response = self.llm.invoke(prompt)
                
                # Extract text from response
                if hasattr(response, 'content'):
                    diet_plan_text = response.content
                elif isinstance(response, str):
                    diet_plan_text = response
                elif isinstance(response, list):
                    diet_plan_text = '\n'.join(str(item) for item in response)
                else:
                    diet_plan_text = str(response)
                
                # Ensure diet_plan_text is a string
                diet_plan_text = str(diet_plan_text)
                
                # Parse the response into structured format
                parsed_plan = self._parse_diet_plan(diet_plan_text)
                additional_notes = self._extract_additional_notes(diet_plan_text)
                
                return {
                    'user_id': user_id,
                    'assessment_date': assessment_date,
                    'diet_plan': parsed_plan,
                    'additional_recommendations': additional_notes,
                    'health_context': {
                        'bmi': health_metrics.get('bmi', 0),
                        'risk_class': risk_assessment.get('risk_class', 'N/A'),
                        'cardiac_risk': derived_scores.get('cardiac_csr', 0),
                        'diabetic_risk': derived_scores.get('diabetic_csr', 0)
                    }
                }
                
            except Exception as e:
                error_msg = str(e)
                
                # Check if it's a rate limit error
                if 'RESOURCE_EXHAUSTED' in error_msg or '429' in error_msg:
                    if attempt < max_retries - 1:
                        wait_time = retry_delay * (2 ** attempt)
                        print(f"⚠️  Rate limit hit. Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        print(f"❌ Rate limit exceeded after {max_retries} attempts. Returning fallback diet plan.")
                        return self._get_fallback_diet_plan(user_id, risk_assessment_data, assessment_date)
                else:
                    print(f"❌ Error generating diet plan: {error_msg}")
                    import traceback
                    traceback.print_exc()
                    return self._get_fallback_diet_plan(user_id, risk_assessment_data, assessment_date)
    
    def _get_fallback_diet_plan(self, user_id: str, risk_assessment_data: dict, assessment_date: str) -> dict:
        """Return a basic diet plan when API is unavailable"""
        risk_assessment = risk_assessment_data.get('risk_assessment', {})
        health_metrics = risk_assessment_data.get('health_metrics', {})
        derived_scores = risk_assessment_data.get('derived_scores', {})
        
        bmi = health_metrics.get('bmi', 0)
        risk_class = risk_assessment.get('risk_class', 'Moderate')
        cardiac_risk = derived_scores.get('cardiac_csr', 0)
        diabetic_risk = derived_scores.get('diabetic_csr', 0)
        
        # Basic diet plan based on risk level
        if risk_class in ['High', 'Critical'] or bmi > 30 or diabetic_risk < 50:
            meals = [
                {'time': 'Morning', 'meal_type': 'Empty Stomach', 'food': 'Warm water with lemon + 5 soaked almonds'},
                {'time': 'Breakfast', 'meal_type': 'Main Meal', 'food': 'Steel-cut oats with skimmed milk (no sugar) + 1 banana or berries'},
                {'time': 'Mid-Morning', 'meal_type': 'Snack', 'food': 'Apple or orange (low GI fruits)'},
                {'time': 'Lunch', 'meal_type': 'Main Meal', 'food': '2 multigrain roti + moong dal + green leafy vegetable + cucumber-tomato salad'},
                {'time': 'Evening', 'meal_type': 'Snack', 'food': 'Green tea + 10-12 mixed nuts (unsalted)'},
                {'time': 'Dinner', 'meal_type': 'Main Meal', 'food': '1 roti + vegetable soup + grilled paneer/fish (100g)'},
                {'time': 'Night', 'meal_type': 'Optional', 'food': 'Warm turmeric milk (skimmed, no sugar)'}
            ]
            additional_notes = [
                'Drink 10-12 glasses of water daily',
                'Avoid sugar, refined carbs, fried foods, processed foods, and excess salt',
                'Eat every 3-4 hours, finish dinner by 8 PM',
                'Include whole grains, lean proteins, leafy greens, and healthy fats',
                'Consider Omega-3 supplements after consulting your doctor'
            ]
        else:
            meals = [
                {'time': 'Morning', 'meal_type': 'Empty Stomach', 'food': 'Water + 5-6 almonds + 2 walnuts'},
                {'time': 'Breakfast', 'meal_type': 'Main Meal', 'food': 'Poha with vegetables OR 2 boiled eggs + whole wheat toast + cup of milk'},
                {'time': 'Mid-Morning', 'meal_type': 'Snack', 'food': 'Seasonal fruit (banana, apple, or papaya)'},
                {'time': 'Lunch', 'meal_type': 'Main Meal', 'food': '2-3 whole wheat roti + dal + seasonal vegetable + curd + cucumber salad'},
                {'time': 'Evening', 'meal_type': 'Snack', 'food': 'Sprouts chaat (with lemon) OR roasted chana (1 cup)'},
                {'time': 'Dinner', 'meal_type': 'Main Meal', 'food': '2 roti + vegetable curry + dal + buttermilk'},
                {'time': 'Night', 'meal_type': 'Optional', 'food': 'Warm milk or herbal tea'}
            ]
            additional_notes = [
                'Drink 8-10 glasses of water daily',
                'Limit processed foods, high-sugar items, and excess salt',
                'Maintain regular meal intervals (3-4 hours), avoid late dinners',
                'Stay physically active for at least 30 minutes daily',
                'Get 7-8 hours of quality sleep'
            ]
        
        return {
            'user_id': user_id,
            'assessment_date': assessment_date,
            'diet_plan': meals,
            'additional_recommendations': additional_notes,
            'health_context': {
                'bmi': bmi,
                'risk_class': risk_class,
                'cardiac_risk': cardiac_risk,
                'diabetic_risk': diabetic_risk
            },
            'note': 'This is a basic diet plan generated due to API limitations. For AI-powered personalized recommendations, please retry later.',
            'fallback': True
        }
    
    def _parse_diet_plan(self, text: str) -> list:
        """Parse diet plan text into structured format"""
        meals = []
        
        # Ensure text is a string
        if not isinstance(text, str):
            text = str(text)
        
        # Split by newlines
        lines = text.split('\n')
        
        # Look for table rows
        for line in lines:
            line = line.strip()
            if '|' in line and line and not line.startswith('Time') and not line.startswith('---'):
                parts = [p.strip() for p in line.split('|')]
                parts = [p for p in parts if p]
                
                if len(parts) >= 3:
                    meals.append({
                        'time': parts[0],
                        'meal_type': parts[1],
                        'food': parts[2] if len(parts) > 2 else ''
                    })
        
        # Fallback if parsing fails
        if not meals or len(meals) < 5:
            print("⚠️  Diet plan parsing failed or incomplete. Using fallback structure.")
            meals = [
                {'time': 'Morning', 'meal_type': 'Empty Stomach', 'food': 'Water + Almonds'},
                {'time': 'Breakfast', 'meal_type': 'Main Meal', 'food': 'Oats / Poha / Eggs'},
                {'time': 'Mid-Morning', 'meal_type': 'Snack', 'food': 'Fruit'},
                {'time': 'Lunch', 'meal_type': 'Main Meal', 'food': 'Roti + Dal + Sabzi + Salad'},
                {'time': 'Evening', 'meal_type': 'Snack', 'food': 'Nuts / Sprouts'},
                {'time': 'Dinner', 'meal_type': 'Main Meal', 'food': 'Light Roti + Sabzi'},
                {'time': 'Night', 'meal_type': 'Optional', 'food': 'Milk'}
            ]
        
        return meals
    
    def _extract_additional_notes(self, text: str) -> list:
        """Extract additional recommendations from the diet plan text"""
        notes = []
        
        if not isinstance(text, str):
            text = str(text)
        
        lines = text.split('\n')
        in_recommendations = False
        
        for line in lines:
            line = line.strip()
            if line and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
                in_recommendations = True
                note = line.lstrip('-•* ').strip()
                if note and len(note) > 10:  # Filter out very short lines
                    notes.append(note)
            elif in_recommendations and line and line[0].isdigit() and '.' in line[:3]:
                note = line.split('.', 1)[1].strip()
                if note and len(note) > 10:
                    notes.append(note)
        
        if not notes:
            notes = [
                'Drink 8-10 glasses of water throughout the day',
                'Avoid processed foods, excess sugar, and fried items',
                'Maintain regular meal timings with 3-4 hour gaps',
                'Include variety of colorful vegetables and fruits daily'
            ]
        
        return notes


class DietRecommendationService:
    """Service wrapper for diet recommendations"""
    
    def __init__(self):
        try:
            self.diet_agent = DietRecommendationAgent()
            print("Diet Recommendation Agent initialized successfully")
        except Exception as e:
            print(f"Warning: Diet Recommendation Agent initialization failed: {e}")
            self.diet_agent = None
    
    def get_personalized_diet_plan(self, user_id: str, risk_assessment_data: dict, assessment_date: str) -> dict:
        """
        Get personalized diet plan for user
        
        Args:
            user_id: Patient identifier
            risk_assessment_data: Risk assessment data
            assessment_date: Date of assessment
            
        Returns:
            Complete diet recommendation
        """
        if not self.diet_agent:
            raise RuntimeError("Diet Recommendation Agent not initialized. Check GEMINI_API_KEY")
        
        return self.diet_agent.generate_diet_plan(user_id, risk_assessment_data, assessment_date)


diet_recommendation_service = DietRecommendationService()