#!/usr/bin/env python3

import requests
import re
import urllib.parse
import tldextract
from datetime import datetime
import hashlib
import time

class TrustedDomainAbuseDetector:
    def __init__(self):
        # trusted domains commonly abused
        self.trusted_domains = {
            'googleapis.com', 'storage.googleapis.com', 'drive.google.com',
            'amazonaws.com', 's3.amazonaws.com', 'cloudfront.net',
            'dropbox.com', 'dl.dropboxusercontent.com',
            'onedrive.live.com', 'sharepoint.com',
            'github.io', 'pages.github.com',
            'netlify.app', 'vercel.app', 'herokuapp.com',
            'firebase.com', 'firebaseapp.com',
            'azure.com', 'blob.core.windows.net',
            'bit.ly', 'tinyurl.com', 'short.link'
        }
        
        # suspicious patterns in trusted domain urls
        self.suspicious_patterns = [
            r'[a-f0-9]{8,}',  # long hex strings
            r'[A-Za-z0-9]{20,}',  # very long random strings
            r'(login|signin|verify|account|banking|paypal|amazon)',  # phishing keywords
            r'#.*?(login|verify|account)',  # suspicious fragments
            r'\?.*?redirect.*?=',  # redirect parameters
            r'(urgent|suspended|verify|confirm)',  # urgent language
        ]
    
    def is_trusted_domain(self, url):
        # check if url uses a trusted domain
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            subdomain_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}" if extracted.subdomain else domain
            
            return domain in self.trusted_domains or subdomain_domain in self.trusted_domains
        except:
            return False
    
    def check_suspicious_patterns(self, url):
        # detect suspicious patterns in trusted domain urls
        suspicion_score = 0
        detected_patterns = []
        
        url_lower = url.lower()
        
        for pattern in self.suspicious_patterns:
            matches = re.findall(pattern, url_lower)
            if matches:
                suspicion_score += len(matches)
                detected_patterns.append(f"Pattern '{pattern}': {matches}")
        
        return suspicion_score, detected_patterns
    
    def check_url_structure(self, url):
        # analyze url structure for abuse indicators
        risk_indicators = []
        parsed = urllib.parse.urlparse(url)
        
        # check for suspicious path patterns
        if len(parsed.path) > 100:
            risk_indicators.append("unusually long path")
        
        # check for suspicious query parameters
        if len(parsed.query) > 200:
            risk_indicators.append("unusually long query string")
        
        # check for suspicious fragments
        if len(parsed.fragment) > 100:
            risk_indicators.append("unusually long fragment")
        
        # check for encoded characters abuse
        encoded_chars = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        if encoded_chars > 5:
            risk_indicators.append(f"excessive url encoding ({encoded_chars} encoded chars)")
        
        return risk_indicators
    
    def follow_redirects_safely(self, url, max_redirects=3, timeout=5):
        # safely follow redirects to check final destination
        try:
            session = requests.Session()
            session.max_redirects = max_redirects
            
            # set headers to look like a browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Chrome/91.0.4472.124)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = session.head(url, headers=headers, timeout=timeout, allow_redirects=True)
            
            # get final url after redirects
            final_url = response.url
            redirect_chain = [str(resp.url) for resp in response.history]
            
            return {
                'final_url': final_url,
                'redirect_chain': redirect_chain,
                'redirected': len(redirect_chain) > 0,
                'status_code': response.status_code
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'final_url': url,
                'redirect_chain': [],
                'redirected': False
            }
    
    def analyze_final_destination(self, final_url):
        """analyze the final destination after redirects"""
        if not final_url:
            return 0, []
        
        warnings = []
        risk_score = 0
        
        try:
            extracted = tldextract.extract(final_url)
            final_domain = f"{extracted.domain}.{extracted.suffix}"
            
            # check if final destination is suspicious
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click', 'download']
            if extracted.suffix in suspicious_tlds:
                risk_score += 3
                warnings.append(f"redirects to suspicious tld: {extracted.suffix}")
            
            # check for suspicious domain patterns
            if re.search(r'[0-9]{4,}', final_domain):
                risk_score += 2
                warnings.append("final domain contains long number sequence")
            
            # check for phishing keywords in final domain
            phishing_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'verify', 'secure']
            for keyword in phishing_keywords:
                if keyword in final_domain.lower():
                    risk_score += 2
                    warnings.append(f"final domain contains phishing keyword: {keyword}")
        
        except:
            pass
        
        return risk_score, warnings
    
    def detect_trusted_domain_abuse(self, url):
        """main function to detect trusted domain abuse"""
        result = {
            'url': url,
            'is_trusted_domain': False,
            'is_suspicious': False,
            'risk_score': 0,
            'warnings': [],
            'analysis_details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # check if this is a trusted domain
        if not self.is_trusted_domain(url):
            result['analysis_details']['reason'] = 'not a trusted domain - using normal ml detection'
            return result
        
        result['is_trusted_domain'] = True
        
        # analyze suspicious patterns
        pattern_score, patterns = self.check_suspicious_patterns(url)
        result['risk_score'] += pattern_score
        if patterns:
            result['warnings'].extend(patterns)
        
        # analyze url structure
        structure_issues = self.check_url_structure(url)
        if structure_issues:
            result['risk_score'] += len(structure_issues)
            result['warnings'].extend(structure_issues)
        
        # follow redirects (if risk score is already elevated)
        if result['risk_score'] > 0:
            redirect_info = self.follow_redirects_safely(url)
            result['analysis_details']['redirect_info'] = redirect_info
            
            if redirect_info.get('redirected'):
                result['risk_score'] += 2
                result['warnings'].append("trusted domain redirects to external site")
                
                # analyze final destination
                final_risk, final_warnings = self.analyze_final_destination(redirect_info.get('final_url'))
                result['risk_score'] += final_risk
                result['warnings'].extend(final_warnings)
        
        # determine if suspicious
        result['is_suspicious'] = result['risk_score'] >= 3
        
        return result

def enhance_ml_prediction(original_prediction, original_confidence, abuse_detection_result):
    """enhance ml prediction with trusted domain abuse detection"""
    
    # if original ml says malicious, trust it
    if original_prediction == 1:
        return {
            'final_prediction': 1,
            'final_confidence': original_confidence,
            'method': 'original_ml_detected_malicious',
            'abuse_detection': abuse_detection_result
        }
    
    # if not a trusted domain, use original prediction
    if not abuse_detection_result['is_trusted_domain']:
        return {
            'final_prediction': original_prediction,
            'final_confidence': original_confidence,
            'method': 'original_ml_not_trusted_domain',
            'abuse_detection': abuse_detection_result
        }
    
    # trusted domain abuse detected
    if abuse_detection_result['is_suspicious']:
        # override ml prediction
        enhanced_confidence = min(0.95, 0.7 + (abuse_detection_result['risk_score'] * 0.05))
        return {
            'final_prediction': 1,
            'final_confidence': enhanced_confidence,
            'method': 'trusted_domain_abuse_detected',
            'abuse_detection': abuse_detection_result,
            'original_ml_prediction': original_prediction,
            'original_ml_confidence': original_confidence
        }
    
    # trusted domain but no abuse detected
    return {
        'final_prediction': original_prediction,
        'final_confidence': original_confidence,
        'method': 'trusted_domain_verified_safe',
        'abuse_detection': abuse_detection_result
    }

# example usage
if __name__ == "__main__":
    detector = TrustedDomainAbuseDetector()
    
    # test cases
    test_urls = [
        "https://storage.googleapis.com/a4a4a4/ads.html#urgent-verify-paypal-account",
        "https://bit.ly/urgent-paypal-verify",
        "https://github.io/amazon-security/urgent-login.html",
        "https://www.google.com/search?q=machine+learning"
    ]
    
    for url in test_urls:
        print(f"\ntesting: {url}")
        result = detector.detect_trusted_domain_abuse(url)
        print(f"trusted domain: {result['is_trusted_domain']}")
        print(f"suspicious: {result['is_suspicious']}")
        print(f"risk score: {result['risk_score']}")
        if result['warnings']:
            print(f"warnings: {result['warnings'][:3]}")  # show first 3 