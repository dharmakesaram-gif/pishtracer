import os
import joblib
import numpy as np
import random
from typing import Dict, Any

try:
    from sklearn.ensemble import RandomForestClassifier
except ImportError:
    RandomForestClassifier = None

class PhishingClassifier:
    """
    ML classifier for phishing detection using a rule-based ensemble scorer
    with an optional fallback to a trained demo Random Forest model.
    """
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'demo_model.pkl')

    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.MODEL_PATH) and RandomForestClassifier is not None:
            try:
                self.model = joblib.load(self.MODEL_PATH)
            except Exception as e:
                print(f"Error loading model: {e}")

    def extract_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from an email for ML classification.
        """
        body = email_data.get('body', '')
        subject = email_data.get('subject', '')
        urls = email_data.get('urls', [])
        
        urgency_words = ['urgent', 'immediate', 'action required', 'alert', 'account suspended', 'validate']
        financial_words = ['invoice', 'payment', 'transfer', 'wire', 'bank', 'crypto', 'wallet']
        suspicious_tlds = ['.xyz', '.top', '.buzz', '.click', '.loan', '.gq', '.ml', '.cf', '.tk']

        subject_lower = subject.lower()
        body_lower = body.lower()

        urgency_count = sum(body_lower.count(w) for w in urgency_words) + sum(subject_lower.count(w) for w in urgency_words)
        financial_count = sum(body_lower.count(w) for w in financial_words) + sum(subject_lower.count(w) for w in financial_words)
        
        num_urls = len(urls)
        num_ip_urls = sum(1 for url in urls if any(char.isdigit() for char in url.split('://')[-1].split('/')[0]) and '.' in url) # simplified check for IPs
        
        has_html = '<html' in body_lower or '<body' in body_lower or '<a href' in body_lower
        
        sender = email_data.get('sender', '')
        sender_email = email_data.get('sender_email', '')
        reply_to = email_data.get('reply_to', '')
        
        brand_name_in_sender = any(brand in sender.lower() for brand in ['paypal', 'amazon', 'microsoft', 'apple', 'google'])
        
        domain_mismatch = False
        if sender and sender_email:
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
            if brand_name_in_sender and sender_domain and not any(brand in sender_domain.lower() for brand in ['paypal', 'amazon', 'microsoft', 'apple', 'google']):
                domain_mismatch = True

        has_attachment_mention = 'attached' in body_lower or 'attachment' in body_lower
        
        generic_greetings = ['dear customer', 'dear user', 'dear member', 'dear client']
        greeting_generic = any(greeting in body_lower for greeting in generic_greetings)
        
        reply_to_mismatch = bool(reply_to and reply_to != sender_email)
        
        num_exclamation = subject.count('!') + body.count('!')
        
        words = body.split()
        all_caps_words = [w for w in words if w.isupper() and len(w) > 1]
        all_caps_ratio = len(all_caps_words) / max(len(words), 1)
        
        suspicious_tld = any(any(tld in url for tld in suspicious_tlds) for url in urls) or any(tld in sender_email for tld in suspicious_tlds)

        return {
            'subject_length': len(subject),
            'body_length': len(body),
            'num_urls': num_urls,
            'num_ip_urls': num_ip_urls,
            'has_html': has_html,
            'urgency_word_count': urgency_count,
            'financial_word_count': financial_count,
            'brand_name_in_sender': brand_name_in_sender,
            'domain_mismatch': domain_mismatch,
            'has_attachment_mention': has_attachment_mention,
            'greeting_generic': greeting_generic,
            'reply_to_mismatch': reply_to_mismatch,
            'num_exclamation': num_exclamation,
            'all_caps_ratio': all_caps_ratio,
            'suspicious_tld': suspicious_tld
        }

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict phishing probability based on extracted features.
        Uses a rule-based scorer or trained ML model.
        """
        weights = {
            'num_ip_urls': 15,
            'urgency_word_count': 5,
            'financial_word_count': 4,
            'domain_mismatch': 20,
            'greeting_generic': 10,
            'reply_to_mismatch': 15,
            'suspicious_tld': 15,
            'brand_name_in_sender': 5,
            'num_urls': 1,
            'has_attachment_mention': 3,
            'num_exclamation': 1,
            'all_caps_ratio': 10
        }

        score = 0.0
        feature_importance = {}
        active_indicators = []

        for feature, val in features.items():
            if feature in weights:
                if isinstance(val, bool):
                    if val:
                        score += weights[feature]
                        feature_importance[feature] = weights[feature]
                        active_indicators.append(feature.replace('_', ' '))
                elif isinstance(val, (int, float)):
                    contribution = min(val * weights[feature], weights[feature] * 3) # Cap max contribution
                    if contribution > 0:
                        score += contribution
                        feature_importance[feature] = contribution
                        if feature in ['urgency_word_count', 'financial_word_count']:
                            active_indicators.append(f"{feature.replace('_', ' ')} ({int(val)} instances)")

        # Sigmoid-like normalization to get 0-1 probability
        probability = 1 / (1 + np.exp(-((score - 25) / 10))) if score > 0 else 0.05

        if self.model is not None:
            # Fallback to model if available
            feature_vector = [
                features.get('subject_length', 0), features.get('body_length', 0), features.get('num_urls', 0),
                features.get('num_ip_urls', 0), int(features.get('has_html', False)), features.get('urgency_word_count', 0),
                features.get('financial_word_count', 0), int(features.get('brand_name_in_sender', False)),
                int(features.get('domain_mismatch', False)), int(features.get('has_attachment_mention', False)),
                int(features.get('greeting_generic', False)), int(features.get('reply_to_mismatch', False)),
                features.get('num_exclamation', 0), features.get('all_caps_ratio', 0.0), int(features.get('suspicious_tld', False))
            ]
            try:
                model_prob = self.model.predict_proba([feature_vector])[0][1]
                probability = (probability + model_prob) / 2 # Blend model and rule-based
            except Exception as e:
                pass # Fall back to purely rule-based

        if probability > 0.7:
            risk_level = 'high'
        elif probability > 0.4:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        indicator_text = ", ".join(active_indicators) if active_indicators else "no clear indicators"
        explanation = f"This email exhibits {len(active_indicators)} phishing indicators: {indicator_text}. Combined confidence: {int(probability * 100)}%."

        # Sort feature importance
        sorted_importance = dict(sorted(feature_importance.items(), key=lambda item: item[1], reverse=True))

        return {
            'phishing_probability': probability,
            'risk_level': risk_level,
            'feature_importance': sorted_importance,
            'explanation': explanation
        }

    def train_demo_model(self):
        """
        Train a synthetic Random Forest model for demonstration purposes.
        """
        if RandomForestClassifier is None:
            print("scikit-learn is not installed. Cannot train demo model.")
            return

        print("Training synthetic demo model...")
        X = []
        y = []
        
        # Legitimate emails (class 0)
        for _ in range(200):
            X.append([
                random.randint(10, 100), # subject_length
                random.randint(50, 1000), # body_length
                random.randint(0, 3), # num_urls
                0, # num_ip_urls
                random.choice([0, 1]), # has_html
                random.randint(0, 1), # urgency_word_count
                random.randint(0, 1), # financial_word_count
                0, # brand_name_in_sender
                0, # domain_mismatch
                random.choice([0, 1]), # has_attachment_mention
                0, # greeting_generic
                0, # reply_to_mismatch
                random.randint(0, 2), # num_exclamation
                random.uniform(0, 0.05), # all_caps_ratio
                0 # suspicious_tld
            ])
            y.append(0)
            
        # Phishing emails (class 1)
        for _ in range(200):
            X.append([
                random.randint(5, 50), # subject_length
                random.randint(20, 500), # body_length
                random.randint(1, 5), # num_urls
                random.randint(0, 2), # num_ip_urls
                random.choice([0, 1]), # has_html
                random.randint(1, 5), # urgency_word_count
                random.randint(0, 4), # financial_word_count
                random.choice([0, 1]), # brand_name_in_sender
                random.choice([0, 1]), # domain_mismatch
                random.choice([0, 1]), # has_attachment_mention
                random.choice([0, 1]), # greeting_generic
                random.choice([0, 1]), # reply_to_mismatch
                random.randint(0, 5), # num_exclamation
                random.uniform(0.01, 0.2), # all_caps_ratio
                random.choice([0, 1]) # suspicious_tld
            ])
            y.append(1)
            
        model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        model.fit(X, y)
        
        joblib.dump(model, self.MODEL_PATH)
        self.model = model
        print(f"Demo model saved to {self.MODEL_PATH}")
