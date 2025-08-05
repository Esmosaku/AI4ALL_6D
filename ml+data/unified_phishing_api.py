#!/usr/bin/env python3
import os
import re
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from sklearn.preprocessing import StandardScaler
import pickle
from datetime import datetime
import urllib.parse
from collections import Counter
import tldextract
from bs4 import BeautifulSoup
from textblob import TextBlob
from transformers import AutoTokenizer, AutoModel
import torch
import warnings
from enhanced_url_security import TrustedDomainAbuseDetector, enhance_ml_prediction

# suppress sklearn warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

app = Flask(__name__)

# enable cors
CORS(app, origins=["chrome-extension://*", "http://localhost:*", "https://localhost:*"])

# global model variables
email_model = None
email_scaler = None
bert_tokenizer = None
bert_model = None

url_model = None
url_scaler = None
url_feature_columns = None

# abuse detector
abuse_detector = TrustedDomainAbuseDetector()

def load_models():
    global email_model, email_scaler, bert_tokenizer, bert_model
    global url_model, url_scaler, url_feature_columns
    
    print("loading phishing detection models...")
    
    # load email model
    try:
        with open('optimized_phishing_model.pkl', 'rb') as f:
            email_data = pickle.load(f)
        email_model = email_data['model']
        email_scaler = email_data['scaler']
        
        # load bert
        bert_tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        bert_model = AutoModel.from_pretrained("bert-base-uncased")
        bert_model.eval()
        
        print("email phishing model loaded")
    except Exception as e:
        print(f"email model failed: {e}")
    
    # load url model
    try:
        with open('url_phishing_model.pkl', 'rb') as f:
            url_data = pickle.load(f)
        url_model = url_data['model']
        url_scaler = url_data['scaler']
        url_feature_columns = url_data['feature_columns']
        
        print("url phishing model loaded")
    except Exception as e:
        print(f"url model failed: {e}")
    
    # check if at least one model loaded
    if email_model is None and url_model is None:
        return False
    
    return True

# email processing functions
def count_keywords(text):
    keywords = ["urgent", "verify your account", "click here", "login now", "password reset",
                "account suspended", "update your information", "confirm your identity",
                "secure your account", "action required"]
    text = text.lower()
    counts = {}
    for word in keywords:
        counts["count_" + word.replace(" ", "_")] = len(re.findall(r'\b' + word + r'\b', text))
    return counts

def check_greeting(text):
    greetings = ["dear customer", "dear user", "hello sir", "hello madam", "dear client"]
    first_bit = text.lower()[:200]
    for greeting in greetings:
        if greeting in first_bit:
            return 1
    return 0

def get_sentiment(text):
    blob = TextBlob(text)
    return blob.sentiment.polarity, blob.sentiment.subjectivity

def persuasion_cues(text):
    good_phrases = ["win", "prize", "bonus", "reward"]
    bad_phrases = ["lose", "suspended", "locked", "expired"]
    text = text.lower()
    good_count = 0
    bad_count = 0
    for phrase in good_phrases:
        good_count += len(re.findall(r'\b' + phrase + r'\b', text))
    for phrase in bad_phrases:
        bad_count += len(re.findall(r'\b' + phrase + r'\b', text))
    return good_count, bad_count

def get_lengths(subject, body):
    return len(subject), len(body.split())

def count_html_tags(text):
    soup = BeautifulSoup(text, 'html.parser')
    return len(soup.find_all())

def count_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return len(re.findall(url_pattern, text))

def count_attachments(text):
    return text.lower().count("content-disposition: attachment")

def count_exclamation(text):
    return text.count("!")

def get_bert_embeddings(text, max_length=512):
    global bert_tokenizer, bert_model
    
    inputs = bert_tokenizer(
        text, 
        return_tensors="pt", 
        truncation=True, 
        max_length=max_length, 
        padding=True
    )
    
    with torch.no_grad():
        outputs = bert_model(**inputs)
        embedding = outputs.last_hidden_state[:, 0, :].numpy().flatten()
    
    return embedding

def extract_email_features(subject, body, from_email):
    combined_text = subject + ' ' + body
    features = {}
    
    features.update(count_keywords(combined_text))
    features['generic_greeting'] = check_greeting(body)
    polarity, subjectivity = get_sentiment(body)
    features['polarity'] = polarity
    features['subjectivity'] = subjectivity
    good_count, bad_count = persuasion_cues(body)
    features['good_phrases'] = good_count
    features['bad_phrases'] = bad_count
    sub_len, body_len = get_lengths(subject, body)
    features['subject_length'] = sub_len
    features['body_length'] = body_len
    features['html_tags'] = count_html_tags(body)
    features['url_count'] = count_urls(body)
    features['attachment_count'] = count_attachments(body)
    features['exclamation_count'] = count_exclamation(combined_text)
    
    features_df = pd.DataFrame([features])
    bert_embedding = get_bert_embeddings(combined_text)
    bert_columns = [f'bert_dim_{i}' for i in range(len(bert_embedding))]
    bert_df = pd.DataFrame([bert_embedding], columns=bert_columns)
    final_df = pd.concat([features_df, bert_df], axis=1)
    
    return final_df

# url processing functions
def extract_url_features(url):
    features = {}
    parsed = urllib.parse.urlparse(url)
    extracted = tldextract.extract(url)

    # structural features
    features['url_length'] = len(url)
    features['domain_length'] = len(parsed.netloc)
    features['path_length'] = len(parsed.path)
    features['query_length'] = len(parsed.query) if parsed.query else 0
    subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
    features['subdomain_count'] = len([s for s in subdomains if s])

    # character features
    features['dot_count'] = url.count('.')
    features['dash_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['slash_count'] = url.count('/')
    features['question_count'] = url.count('?')
    features['equal_count'] = url.count('=')
    features['at_count'] = url.count('@')
    features['ampersand_count'] = url.count('&')
    features['exclamation_count'] = url.count('!')
    features['space_count'] = url.count(' ')
    features['tilde_count'] = url.count('~')
    features['comma_count'] = url.count(',')
    features['plus_count'] = url.count('+')
    features['asterisk_count'] = url.count('*')
    features['hash_count'] = url.count('#')
    features['dollar_count'] = url.count('$')
    features['percent_count'] = url.count('%')
    
    hex_pattern = r'%[0-9A-Fa-f]{2}'
    features['hex_encoding_count'] = len(re.findall(hex_pattern, url))
    features['has_hex_encoding'] = 1 if features['hex_encoding_count'] > 0 else 0
    
    digit_count = sum(c.isdigit() for c in url)
    features['digit_count'] = digit_count
    features['digit_ratio'] = digit_count / len(url) if len(url) > 0 else 0
    
    letter_count = sum(c.isalpha() for c in url)
    features['letter_count'] = letter_count
    features['letter_ratio'] = letter_count / len(url) if len(url) > 0 else 0

    # domain features
    common_tlds = ['com', 'org', 'net', 'gov', 'edu', 'mil']
    features['is_common_tld'] = 1 if extracted.suffix in common_tlds else 0
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click', 'download']
    features['is_suspicious_tld'] = 1 if extracted.suffix in suspicious_tlds else 0

    # parameter features
    query_params = urllib.parse.parse_qs(parsed.query)
    features['param_count'] = len(query_params)

    # suspicious keywords
    suspicious_keywords = [
        'login', 'signin', 'account', 'banking', 'secure', 'security', 'verify',
        'update', 'confirm', 'validation', 'authenticate', 'paypal', 'ebay',
        'amazon', 'microsoft', 'apple', 'google', 'facebook', 'twitter',
        'suspended', 'limited', 'verification', 'urgent', 'immediate'
    ]
    url_lower = url.lower()
    features['suspicious_keyword_count'] = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    features['has_suspicious_keywords'] = 1 if features['suspicious_keyword_count'] > 0 else 0

    # protocol features
    features['is_https'] = 1 if parsed.scheme == 'https' else 0
    features['is_http'] = 1 if parsed.scheme == 'http' else 0

    # statistical features
    def calculate_entropy(text):
        if not text:
            return 0
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * np.log2(count/length) for count in counter.values())
        return entropy
    
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(extracted.domain)
    
    vowels = 'aeiouAEIOU'
    vowel_count = sum(1 for char in url if char in vowels)
    features['vowel_count'] = vowel_count
    features['vowel_ratio'] = vowel_count / len(url) if len(url) > 0 else 0
    
    consecutive_chars = re.findall(r'(.)\1+', url)
    features['consecutive_char_count'] = len(consecutive_chars)
    features['max_consecutive_chars'] = max([len(match) + 1 for match in consecutive_chars]) if consecutive_chars else 0

    return features

def make_email_prediction(subject, body, from_email):
    global email_model, email_scaler
    
    features = extract_email_features(subject, body, from_email)
    scaled_features = email_scaler.transform(features)
    
    prediction = email_model.predict(scaled_features)[0]
    probability = email_model.predict_proba(scaled_features)[0]
    confidence = max(probability)
    
    return int(prediction), float(confidence)

def make_url_prediction(url):
    global url_model, url_scaler, url_feature_columns, abuse_detector
    
    # get original ml prediction
    features = extract_url_features(url)
    features_df = pd.DataFrame([features])
    
    # ensure all required columns exist
    for col in url_feature_columns:
        if col not in features_df.columns:
            features_df[col] = 0
    
    features_df = features_df[url_feature_columns]
    scaled_features = url_scaler.transform(features_df)
    
    original_prediction = url_model.predict(scaled_features)[0]
    probability = url_model.predict_proba(scaled_features)[0]
    original_confidence = max(probability)
    
    # check for trusted domain abuse
    abuse_result = abuse_detector.detect_trusted_domain_abuse(url)
    
    # enhance prediction with abuse detection
    enhanced_result = enhance_ml_prediction(
        int(original_prediction), 
        float(original_confidence), 
        abuse_result
    )
    
    return enhanced_result

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'email_model_loaded': email_model is not None,
        'url_model_loaded': url_model is not None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict/email', methods=['POST'])
def predict_email():
    if email_model is None:
        return jsonify({'error': 'email model not available'}), 503
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'no data provided'}), 400
        
        subject = data.get('subject', '')
        body = data.get('body', '')
        from_email = data.get('from', '')
        
        if not subject and not body:
            return jsonify({'error': 'subject or body is required'}), 400
        
        prediction, confidence = make_email_prediction(subject, body, from_email)
        
        result = {
            'type': 'email',
            'isPhishing': bool(prediction),
            'prediction': prediction,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'email prediction failed: {str(e)}'}), 500

@app.route('/predict/url', methods=['POST'])
def predict_url():
    if url_model is None:
        return jsonify({'error': 'url model not available'}), 503
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'no data provided'}), 400
        
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'url is required'}), 400
        
        enhanced_result = make_url_prediction(url)
        
        result = {
            'type': 'url',
            'isPhishing': bool(enhanced_result['final_prediction']),
            'prediction': enhanced_result['final_prediction'],
            'confidence': enhanced_result['final_confidence'],
            'detection_method': enhanced_result['method'],
            'url': url,
            'timestamp': datetime.now().isoformat()
        }
        
        # add trusted domain analysis
        if enhanced_result['abuse_detection']['is_trusted_domain']:
            result['trusted_domain_analysis'] = {
                'is_trusted_domain': True,
                'abuse_detected': enhanced_result['abuse_detection']['is_suspicious'],
                'risk_score': enhanced_result['abuse_detection']['risk_score'],
                'warnings': enhanced_result['abuse_detection']['warnings'][:5]
            }
            
        # add original ml info if enhanced
        if 'original_ml_prediction' in enhanced_result:
            result['original_ml_result'] = {
                'prediction': enhanced_result['original_ml_prediction'],
                'confidence': enhanced_result['original_ml_confidence']
            }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'url prediction failed: {str(e)}'}), 500

@app.route('/predict', methods=['POST'])
def predict_auto():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'no data provided'}), 400
        
        # auto-detect type based on request content
        if 'url' in data:
            enhanced_result = make_url_prediction(data['url'])
            
            result = {
                'type': 'url',
                'isPhishing': bool(enhanced_result['final_prediction']),
                'prediction': enhanced_result['final_prediction'],
                'confidence': enhanced_result['final_confidence'],
                'detection_method': enhanced_result['method'],
                'url': data['url'],
                'timestamp': datetime.now().isoformat()
            }
            
            # add trusted domain analysis if applicable
            if enhanced_result['abuse_detection']['is_trusted_domain']:
                result['trusted_domain_analysis'] = {
                    'is_trusted_domain': True,
                    'abuse_detected': enhanced_result['abuse_detection']['is_suspicious'],
                    'risk_score': enhanced_result['abuse_detection']['risk_score'],
                    'warnings': enhanced_result['abuse_detection']['warnings'][:3]
                }
            
            return jsonify(result)
            
        elif 'subject' in data or 'body' in data:
            return predict_email()
        else:
            return jsonify({'error': 'provide either url or email data'}), 400
            
    except Exception as e:
        return jsonify({'error': f'prediction failed: {str(e)}'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'internal server error'}), 500

# start the app
if __name__ == '__main__':
    print("unified phishing detection api")
    print("=" * 40)
    
    if load_models():
        print("starting flask server...")
        print("available endpoints:")
        print("- post /predict - auto-detect email or url")
        print("- post /predict/email - email phishing detection")
        print("- post /predict/url - url phishing detection")
        print("- get /health - health check")
        print("")
        print("unified api endpoint: http://localhost:5003/predict")
        
        app.run(host='0.0.0.0', port=5003, debug=True)
    else:
        print("failed to load any models")
        print("make sure model files exist in this directory") 