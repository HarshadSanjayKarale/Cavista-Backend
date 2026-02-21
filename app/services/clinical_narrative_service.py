"""
Clinical Narrative Service
Multi-agent system for generating clinical narratives from risk assessments
"""
import os
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from dotenv import load_dotenv

load_dotenv()

class ClinicalNarrativeAgent:
    """Agent 1: Risk Interpreter - Generates clinical narratives from risk data"""
    
    def __init__(self):
        # Initialize Gemini LLM with the correct model name
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-3-flash-preview",  # Updated to latest Gemini model
            google_api_key=os.getenv('GEMINI_API_KEY'),
            temperature=0.3,
            convert_system_message_to_human=True
        )
        
        # Comprehensive prompt for clinical narrative generation
        self.prompt_template = """You are an experienced clinical health analyst interpreting health risk assessment data.

**PATIENT ID:** {user_id}

**RISK ASSESSMENT DATA:**
{risk_data}

**YOUR TASK:**
Generate a comprehensive, professional clinical narrative that:

1. **Risk Overview**: Start with the overall risk classification and probability in clear terms
2. **Key Health Metrics Analysis**: Interpret the actual health metrics (steps, sleep, heart rate, BMI, etc.)
3. **Derived Health Scores**: Explain what the health score, cardiac CSR, diabetic CSR, and sleep score indicate
4. **SHAP Factor Analysis**: Explain which factors are INCREASING risk (positive contributions) and which are PROTECTING (negative contributions)
5. **Top Contributing Factors**: Focus on the top 3-5 factors driving the risk assessment
6. **Clinical Significance**: Explain what these findings mean for the patient's health
7. **Actionable Insights**: Provide 2-3 specific, evidence-based recommendations

**STYLE GUIDELINES:**
- Use clear, professional medical terminology but keep it understandable
- Be direct and specific with numbers when relevant
- Avoid being alarmist, but be honest about risks
- Structure the narrative with clear sections
- Focus on actionable insights the patient can use
- Mention both positive aspects and areas of concern

**OUTPUT FORMAT:**
Structure your response as a clinical report with these sections:
- Executive Summary
- Risk Assessment
- Health Metrics Analysis
- Risk Factor Contributions
- Clinical Recommendations

Generate a comprehensive clinical narrative now:"""
    
    def generate_narrative(self, user_id: str, risk_assessment_data: dict) -> str:
        """
        Generate clinical narrative from risk assessment data
        
        Args:
            user_id: Patient identifier
            risk_assessment_data: Complete risk assessment output from ML model
            
        Returns:
            Clinical narrative as formatted text
        """
        try:
            # Format the risk data for better LLM understanding
            formatted_data = self._format_risk_data(risk_assessment_data)
            
            # Create the prompt
            prompt = self.prompt_template.format(
                user_id=user_id,
                risk_data=formatted_data
            )
            
            # Generate narrative using LLM
            response = self.llm.invoke(prompt)
            
            # Extract text from response
            if hasattr(response, 'content'):
                narrative = response.content
            else:
                narrative = str(response)
            
            return narrative
            
        except Exception as e:
            print(f"❌ Error generating narrative: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
    
    def _format_risk_data(self, data: dict) -> str:
        """Format risk assessment data for LLM consumption"""
        
        # Extract key components
        risk_assessment = data.get('risk_assessment', {})
        health_metrics = data.get('health_metrics', {})
        derived_scores = data.get('derived_scores', {})
        risk_factors = data.get('risk_factors', {})
        recommendations = data.get('recommendations', [])
        
        # Format as structured text
        formatted = f"""
## OVERALL RISK ASSESSMENT
- Risk Class: {risk_assessment.get('risk_class', 'N/A')}
- Risk Probability: {risk_assessment.get('risk_probability', 0):.4f} ({risk_assessment.get('risk_percentage', 0):.2f}%)
- Assessment Date: {risk_assessment.get('assessment_date', 'N/A')}

## HEALTH METRICS (Raw Data)
- Daily Steps: {health_metrics.get('steps', 0):,}
- Calories Burned: {health_metrics.get('calories', 0):,}
- Distance Covered: {health_metrics.get('distance_km', 0)} km
- Sleep Duration: {health_metrics.get('sleep_hrs', 0)} hours
- Active Minutes: {health_metrics.get('active_min', 0)} minutes
- Resting Heart Rate: {health_metrics.get('heart_rate', 0)} bpm
- Body Mass Index (BMI): {health_metrics.get('bmi', 0)}

## DERIVED HEALTH SCORES
- Overall Health Score: {derived_scores.get('health_score', 0):.2f}/100
- Cardiac Risk Score (CSR): {derived_scores.get('cardiac_csr', 0):.2f}
- Diabetic Risk Score (CSR): {derived_scores.get('diabetic_csr', 0):.2f}/100
- Sleep Quality Score: {derived_scores.get('sleep_score', 0):.2f}/100

## TOP RISK CONTRIBUTING FACTORS (SHAP Analysis)
"""
        
        # Add top contributing factors
        top_factors = risk_factors.get('top_contributing_factors', [])
        for i, factor in enumerate(top_factors, 1):
            impact = factor.get('impact', 'Unknown')
            contribution = factor.get('contribution', 0)
            feature = factor.get('feature', 'Unknown')
            formatted += f"{i}. {feature}: {contribution:+.4f} ({impact})\n"
        
        # Add recommendations if available
        if recommendations:
            formatted += "\n## INITIAL RECOMMENDATIONS FROM MODEL\n"
            for i, rec in enumerate(recommendations[:3], 1):
                formatted += f"{i}. [{rec.get('priority', 'N/A')}] {rec.get('category', 'N/A')}: {rec.get('message', 'N/A')}\n"
        
        return formatted


class ClinicalNarrativeService:
    """Service wrapper for clinical narrative generation"""
    
    def __init__(self):
        try:
            self.risk_interpreter = ClinicalNarrativeAgent()
            print("✅ Clinical Narrative Agent initialized successfully (Gemini 2.0 Flash)")
        except Exception as e:
            print(f"⚠️  Warning: Clinical Narrative Agent could not be initialized: {e}")
            self.risk_interpreter = None
    
    def generate_comprehensive_report(self, user_id: str, risk_assessment_data: dict) -> dict:
        """
        Generate comprehensive clinical report
        
        Args:
            user_id: Patient identifier
            risk_assessment_data: Risk assessment output from ML model
            
        Returns:
            Complete report with narrative and structured data
        """
        if not self.risk_interpreter:
            raise RuntimeError("Clinical Narrative Agent is not initialized. Check GEMINI_API_KEY in .env")
        
        try:
            # Generate clinical narrative
            clinical_narrative = self.risk_interpreter.generate_narrative(
                user_id=user_id,
                risk_assessment_data=risk_assessment_data
            )
            
            # Combine with original data
            report = {
                'user_id': user_id,
                'clinical_narrative': clinical_narrative,
                'structured_assessment': risk_assessment_data,
                'report_metadata': {
                    'generated_by': 'AI Clinical Narrative System (Gemini 2.0 Flash)',
                    'model_version': 'v1.0',
                    'agent_type': 'Risk Interpreter Agent',
                    'llm_model': 'gemini-3-flash-preview'
                }
            }
            
            return report
            
        except Exception as e:
            print(f"❌ Error generating clinical report: {str(e)}")
            import traceback
            traceback.print_exc()
            raise


# Singleton instance
clinical_narrative_service = ClinicalNarrativeService()