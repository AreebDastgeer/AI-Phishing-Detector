from urllib.parse import urlparse
import re
import difflib
import math
from collections import Counter
import tldextract

def suspicious_subdomain(url):
    ext = tldextract.extract(url)

    subdomain = ext.subdomain
    domain = ext.domain
    suffix = ext.suffix

    suspicious_brands = [
        "google",
        "youtube",
        "paypal",
        "facebook",
        "amazon"
    ]

    # brand appears in subdomain instead of real domain
    return 1 if any(b in subdomain for b in suspicious_brands) else 0

def similarity(url):
    domain = urlparse(url).netloc.lower()

    trusted = ["google.com", "facebook.com", "paypal.com"]

    return max([
        difflib.SequenceMatcher(None, domain, t).ratio()
        for t in trusted
    ])



def entropy(url):
    probs = [c / len(url) for c in Counter(url).values()]
    return -sum(p * math.log2(p) for p in probs)

def char_diversity(url):
    return len(set(url)) / len(url)

def subdomain_depth(url):
    domain = urlparse(url).netloc
    return domain.count('.')

def extract_features(url):


    features = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. URL length
    features.append(len(url))

    # 2. HTTPS presence
    features.append(1 if "https" in url else 0)

    # 3. Count dots (subdomains)
    features.append(url.count('.'))

    # 4. Hyphens
    features.append(url.count('-'))

    # 5. @ symbol
    features.append(url.count('@'))

    # 6. Slashes
    features.append(url.count('/'))

    # 7. Question marks
    features.append(url.count('?'))

    # 8. Equal signs
    features.append(url.count('='))

    # 9. Digit count
    features.append(sum(c.isdigit() for c in url))

    # 10. IP address in domain
    features.append(1 if re.match(r"^\d+\.\d+\.\d+\.\d+", domain) else 0)

    # 11. Suspicious keywords
    path = parsed.path.lower()

    suspicious = ['login','verify','secure','bank','update','account','free']

    features.append(
        1 if any(w in path for w in suspicious) else 0
    )

    # 12. Domain length 
    features.append(len(domain))

    # 13. Ratio of digits in domain 
    features.append(sum(c.isdigit() for c in domain) / (len(domain) + 1))

    # 14. Similarity to trusted domains 
    features.append(similarity(url))

    features.append(entropy(url))            
    features.append(char_diversity(url))     
    features.append(subdomain_depth(url))    
    features.append(suspicious_subdomain(url))

    print(len(features))

    return features