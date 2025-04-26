import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    
    features['length'] = len(url)
    features['has_ip'] = bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', url))
    features['has_https'] = url.startswith('https')
    features['has_at'] = '@' in url
    features['has_hyphen'] = '-' in urlparse(url).netloc
    features['dot_count'] = url.count('.')
    features['has_suspicious_words'] = any(word in url.lower() for word in ['login', 'secure', 'bank', 'update', 'verify'])

    return features

def is_phishing(features):
    score = 0
    
    if features['length'] > 75: score += 1
    if features['has_ip']: score += 2
    if not features['has_https']: score += 1
    if features['has_at']: score += 2
    if features['has_hyphen']: score += 1
    if features['dot_count'] > 4: score += 1
    if features['has_suspicious_words']: score += 2

    return score >= 4
