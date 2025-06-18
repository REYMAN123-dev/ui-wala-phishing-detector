from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
import google.generativeai as genai
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
import os
import re
from pydantic import validator

# Set Gemini API key directly
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDDomIGM7rf41xk9Jsmx63rGMj85Uh3QKY'

# Configure Gemini
genai.configure(api_key=os.environ['GOOGLE_API_KEY'])
model = genai.GenerativeModel("gemini-1.5-flash")

# Knowledge base for phishing detection and security
PHISHING_KNOWLEDGE_BASE = """
PHISHING DETECTION KNOWLEDGE BASE:

1. PHISHING INDICATORS:
- Urgency or pressure tactics ("Act now!", "Limited time offer!")
- Poor grammar and spelling errors
- Suspicious sender email addresses
- Requests for sensitive information (passwords, credit cards, SSN)
- Generic greetings instead of personal names
- Suspicious links that don't match the sender
- Threats or consequences for not acting
- Offers that seem too good to be true

2. URL ANALYSIS:
- Check for HTTPS vs HTTP
- Look for domain mismatches
- Verify the domain is legitimate
- Check for suspicious redirects
- Look for typosquatting (similar but misspelled domains)
- Verify SSL certificates
- Check domain age and reputation

3. EMAIL ANALYSIS:
- Analyze sender information
- Check email headers for spoofing
- Look for suspicious attachments
- Verify email authentication (SPF, DKIM, DMARC)
- Check for urgency or pressure tactics
- Analyze content for suspicious requests
- Verify branding consistency

4. SECURITY BEST PRACTICES:
- Never click suspicious links
- Verify sender addresses carefully
- Don't share sensitive information via email
- Use two-factor authentication
- Keep software and systems updated
- Use strong, unique passwords
- Be skeptical of unsolicited requests
- Report suspicious emails to IT security

5. RISK SCORING:
- 0-30: Low risk - Likely legitimate
- 31-70: Medium risk - Exercise caution
- 71-100: High risk - Likely phishing attempt

6. TOOL USAGE:
- URL Analysis: Paste complete URL including protocol
- Email Analysis: Include headers for best results
- Always verify results with additional checks
- Use multiple detection methods for confirmation

7. COMMON PHISHING TYPES:
- Spear phishing (targeted attacks)
- Whaling (targeting executives)
- Vishing (voice phishing)
- Smishing (SMS phishing)
- Clone phishing (copying legitimate emails)
- Business email compromise (BEC)

8. RESPONSE GUIDELINES:
- Provide clear, actionable advice
- Explain technical concepts simply
- Always prioritize user safety
- Suggest additional verification steps
- Encourage reporting suspicious activity
- REDIRECT users to analysis tools for URL/email analysis
- DO NOT provide direct analysis in chat - use tools instead

9. REDIRECTION RULES:
- If user asks to analyze a URL: Redirect to URL analysis tool
- If user asks to analyze an email: Redirect to email analysis tool
- If user provides a URL: Redirect to URL analysis tool
- If user provides email content: Redirect to email analysis tool
- If user asks about specific analysis: Guide them to appropriate tool
- Only provide general advice and education in chat
- Never perform actual analysis in chat responses
"""

# Define PhishingResult model
class PhishingResult(BaseModel):
    risk_score: int
    analysis: str
    indicators: List[str]
    confidence: float

# Create agent with the model
class Agent:
    def __init__(self, output_type, model):
        self.output_type = output_type
        self.model = model

    def extract_risk_score(self, text: str) -> int:
        score_match = re.search(r'risk\s*score:?\s*(\d+)', text.lower())
        if score_match:
            return int(score_match.group(1))
        return 50

    def extract_indicators(self, text: str) -> List[str]:
        indicators = []
        indicator_patterns = [
            r'urgency',
            r'suspicious',
            r'grammar',
            r'spelling',
            r'domain',
            r'certificate',
            r'legitimate',
            r'branding',
            r'inconsistencies',
            r'pressure tactics',
            r'phishing',
            r'scam',
            r'fake',
            r'fraudulent'
        ]
        
        for pattern in indicator_patterns:
            if re.search(pattern, text.lower()):
                sentences = text.split('.')
                for sentence in sentences:
                    if pattern in sentence.lower():
                        indicators.append(sentence.strip())
        
        return indicators[:5]

    def calculate_confidence(self, text: str) -> float:
        confidence = 0.5  # Base confidence
        
        # Check for definitive indicators
        definitive_indicators = [
            r'definitely|clearly|certainly|confirmed|verified',
            r'high risk|severe risk|critical risk',
            r'multiple indicators|several indicators',
            r'confirmed phishing|verified scam',
            r'known phishing pattern|known scam pattern'
        ]
        
        for pattern in definitive_indicators:
            if re.search(pattern, text.lower()):
                confidence += 0.1
        
        # Check for analysis depth
        if len(text.split()) > 100:  # Detailed analysis
            confidence += 0.1
        if len(text.split('\n')) > 5:  # Well-structured analysis
            confidence += 0.1
            
        # Check for specific technical indicators
        technical_indicators = [
            r'spam score|spf|dkim|dmarc',
            r'domain mismatch|email spoofing',
            r'ssl certificate|security certificate',
            r'ip address|dns record',
            r'header analysis|email header'
        ]
        
        for pattern in technical_indicators:
            if re.search(pattern, text.lower()):
                confidence += 0.05
        
        # Check for risk score correlation
        risk_score = self.extract_risk_score(text)
        if risk_score > 80:
            confidence += 0.1
        elif risk_score > 60:
            confidence += 0.05
            
        # Ensure confidence is between 0.5 and 0.95
        return min(max(confidence, 0.5), 0.95)

    def analyze(self, prompt: str) -> PhishingResult:
        response = self.model.generate_content(prompt)
        analysis_text = response.text

        risk_score = self.extract_risk_score(analysis_text)
        indicators = self.extract_indicators(analysis_text)
        confidence = self.calculate_confidence(analysis_text)

        analysis_text = re.sub(r'risk\s*score:?\s*\d+', '', analysis_text, flags=re.IGNORECASE)
        analysis_text = re.sub(r'\n+', '\n', analysis_text).strip()

        return PhishingResult(
            risk_score=risk_score,
            analysis=analysis_text,
            indicators=indicators,
            confidence=confidence
        )

    def chat_response(self, user_message: str) -> str:
        """Generate intelligent chat responses using knowledge base"""
        
        # Check if user is asking for URL or email analysis
        user_message_lower = user_message.lower()
        
        # URL analysis detection patterns
        url_patterns = [
            r'analyze.*url',
            r'check.*url',
            r'is.*url.*safe',
            r'url.*phishing',
            r'http[s]?://',
            r'www\.',
            r'\.com',
            r'\.org',
            r'\.net',
            r'\.io',
            r'\.co',
            r'\.uk',
            r'\.de',
            r'\.fr',
            r'\.jp',
            r'\.cn',
            r'\.in',
            r'\.br',
            r'\.au',
            r'\.ca'
        ]
        
        # Email analysis detection patterns
        email_patterns = [
            r'analyze.*email',
            r'check.*email',
            r'is.*email.*safe',
            r'email.*phishing',
            r'@.*\.',
            r'from:',
            r'to:',
            r'subject:',
            r'dear.*user',
            r'urgent.*action',
            r'account.*suspended',
            r'password.*expired',
            r'verify.*account',
            r'click.*here',
            r'limited.*time',
            r'act.*now'
        ]
        
        # Check for URL patterns
        is_url_request = any(re.search(pattern, user_message_lower) for pattern in url_patterns)
        
        # Check for email patterns
        is_email_request = any(re.search(pattern, user_message_lower) for pattern in email_patterns)
        
        if is_url_request:
            return """🔗 I can help you analyze that URL! 

For the most accurate and detailed analysis, please use our dedicated URL Analysis tool:

1. Scroll down to the "URL Analysis" section
2. Paste the complete URL (including http:// or https://)
3. Click "Analyze URL"

Our AI will provide you with:
• Risk score (0-100)
• Detailed analysis
• Key indicators
• Confidence level
• Specific recommendations

This gives you much more comprehensive results than I can provide in chat! 🚀"""
        
        elif is_email_request:
            return """📧 I can help you analyze that email! 

For the most accurate and detailed analysis, please use our dedicated Email Analysis tool:

1. Scroll down to the "Email Analysis" section
2. Paste the complete email content (including headers if possible)
3. Click "Analyze Email"

Our AI will provide you with:
• Risk score (0-100)
• Detailed analysis
• Key indicators
• Confidence level
• Specific recommendations

This gives you much more comprehensive results than I can provide in chat! 🚀"""
        
        # Regular knowledge base response for other questions
        prompt = f"""
        You are an AI security assistant for PhishGuard Pro, a phishing detection system. 
        Use the following knowledge base to provide helpful, accurate responses:

        {PHISHING_KNOWLEDGE_BASE}

        USER MESSAGE: {user_message}

        Instructions:
        1. Provide clear, helpful responses based on the knowledge base
        2. Keep responses concise but informative (2-4 sentences)
        3. Use a friendly, professional tone
        4. Include specific tips when relevant
        5. If the question is not covered in the knowledge base, provide general security advice
        6. Always prioritize user safety and security
        7. DO NOT provide direct URL or email analysis - redirect to tools instead
        8. Focus on education and guidance, not direct analysis

        RESPONSE:
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            print(f"Error generating chat response: {str(e)}")
            return "I apologize, but I'm having trouble processing your request right now. Please try again in a moment, or use our URL and email analysis tools for immediate phishing detection."

agent = Agent(output_type=PhishingResult, model=model)

app = Flask(__name__)
CORS(app)

# Pydantic models for request validation
class URLRequest(BaseModel):
    url: HttpUrl

    @validator('url')
    def validate_url(cls, v):
        if not v or len(str(v).strip()) == 0:
            raise ValueError('URL cannot be empty')
        return v

class EmailRequest(BaseModel):
    email_content: str

    @validator('email_content')
    def validate_email_content(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Email content cannot be empty')
        return v.strip()

class ChatRequest(BaseModel):
    message: str

    @validator('message')
    def validate_message(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Message cannot be empty')
        return v.strip()

def analyze_with_gemini(prompt: str) -> PhishingResult:
    try:
        return agent.analyze(prompt)
    except Exception as e:
        print(f"Error in Gemini analysis: {str(e)}")
        raise

@app.route('/')
def home():
    return redirect(url_for('choose_analysis'))

@app.route('/choose-analysis')
def choose_analysis():
    return render_template('choose_analysis.html')

@app.route('/url-analysis')
def url_analysis():
    return render_template('url_analysis.html')

@app.route('/email-analysis')
def email_analysis():
    return render_template('email_analysis.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """AI Chatbot endpoint using Gemini AI"""
    try:
        if not request.json or 'message' not in request.json:
            return jsonify({"error": "Message is required"}), 400
            
        data = ChatRequest(**request.json)
        response = agent.chat_response(data.message)
        
        return jsonify({
            "response": response,
            "timestamp": "now"
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in chat: {str(e)}")
        return jsonify({"error": "An error occurred while processing your message. Please try again."}), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    try:
        if not request.json or 'url' not in request.json:
            return jsonify({"error": "URL is required"}), 400
            
        data = URLRequest(**request.json)
        prompt = f"""
        Analyze this URL for phishing: {data.url}

        Provide a concise analysis in this exact format:
        Risk Score: [0-100]
        
        Key Findings:
        - [List 3-4 most important findings]
        
        Indicators:
        - [List specific phishing indicators found]
        
        Recommendation:
        [One sentence recommendation]

        Keep the analysis brief and focused on critical security aspects.
        """
        
        result = analyze_with_gemini(prompt)
        return jsonify({
            "analysis": result.analysis,
            "risk_score": result.risk_score,
            "indicators": result.indicators,
            "confidence": result.confidence
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in URL analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the URL. Please try again."}), 500

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    try:
        if not request.json or 'email_content' not in request.json:
            return jsonify({"error": "Email content is required"}), 400
            
        data = EmailRequest(**request.json)
        prompt = f"""
        Analyze this email for phishing: {data.email_content}

        Provide a concise analysis in this exact format:
        Risk Score: [0-100]
        
        Key Findings:
        - [List 3-4 most important findings]
        
        Indicators:
        - [List specific phishing indicators found]
        
        Recommendation:
        [One sentence recommendation]

        Focus on:
        1. Sender information and email address legitimacy
        2. Urgency or pressure tactics in the content
        3. Suspicious links or attachments
        4. Grammar and spelling errors
        5. Request for sensitive information
        6. Email header analysis
        7. Domain and email address mismatches
        8. Generic greetings or poor personalization
        """
        
        result = analyze_with_gemini(prompt)
        return jsonify({
            "analysis": result.analysis,
            "risk_score": result.risk_score,
            "indicators": result.indicators,
            "confidence": result.confidence
        })
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error in email analysis: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing the email. Please try again."}), 500

if __name__ == '__main__':
    app.run(debug=True) 