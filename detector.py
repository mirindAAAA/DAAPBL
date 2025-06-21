import re
from collections import defaultdict
import heapq
import urllib.parse
import tldextract
import joblib
import logging
from typing import List, Dict, Set, Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False

class Trie:
    def __init__(self):
        self.root = TrieNode()
    
    def insert(self, word: str) -> None:
        node = self.root
        for char in word.lower():
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True
    
    def search(self, text: str) -> bool:
        text = text.lower()
        n = len(text)
        for i in range(n):
            node = self.root
            for j in range(i, n):
                char = text[j]
                if char not in node.children:
                    break
                node = node.children[char]
                if node.is_end_of_word:
                    return True
        return False

def build_kmp_table(pattern: str) -> List[int]:
    table = [0] * len(pattern)
    length = 0
    i = 1
    
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            table[i] = length
            i += 1
        else:
            if length != 0:
                length = table[length - 1]
            else:
                table[i] = 0
                i += 1
    return table

def kmp_search(text: str, pattern: str) -> bool:
    if not pattern:
        return False
    
    text = text.lower()
    pattern = pattern.lower()
    table = build_kmp_table(pattern)
    i = j = 0
    
    while i < len(text):
        if text[i] == pattern[j]:
            i += 1
            j += 1
            if j == len(pattern):
                return True
        else:
            if j != 0:
                j = table[j - 1]
            else:
                i += 1
    return False

class EmailAnalyzer:
    def __init__(self):
        self.trie = Trie()
        self.common_phishing_keywords = [
            "urgent", "action required", "verify your account", 
            "suspended", "security alert", "click here", "login",
            "password", "bank", "paypal", "irs", "tax", "refund",
            "limited time", "offer", "prize", "won", "free", "gift",
            "account", "update", "confirm", "dear customer", "unauthorized access", 
            "account verification", "password reset", "security update",
            "billing information", "credit card", "social security", 
            "account suspension", "verify your identity", "important notice", 
            "immediate attention", "account closure", "fraud alert", 
            "suspicious activity", "unusual login attempt", "account restricted",
            "payment failed", "invoice attached", "order confirmation", 
            "shipping notification", "document shared", "secure message", 
            "account compromised", "locked out", "temporary hold", 
            "expiration notice", "renew now", "last chance", "exclusive offer", 
            "congratulations", "claim your prize", "you've been selected",
            "limited offer", "act now", "don't miss out", "final warning",
            "account deactivation", "verify now", "click below", 
            "secure your account", "urgent review", "take action", 
            "response required", "attention required", "action", "immediate action",
            "security check", "account security", "identity verification", "verifiy", "verify your email", "secure your account", "account update", "account information"," click to verify", "click to confirm", "click to update", "click to secure", "click to protect", "click to access", "click to claim", "click to redeem", "click to win", "click for details", "click for more information", "click for instructions", "click for help", "click for support", "click for assistance"
        ]
        self.suspicious_domains = set()
        self.model = None
        
        for keyword in self.common_phishing_keywords:
            self.trie.insert(keyword)
    def add_suspicious_domain(self, domain: str) -> None:
        """Add a domain to the suspicious domains set"""
        self.suspicious_domains.add(domain.lower())
    def load_model(self, model_path: str) -> bool:
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Successfully loaded model from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            self.model = None
            return False
    
    def analyze_email(self, email_content: str, sender: str) -> Dict:
        results = {
            "suspicious_content": [],
            "suspicious_sender": False,
            "suspicious_links": [],
            "score": 0,
            "email_analysis": {
                "sender": sender,
                "subject": self._extract_subject(email_content),
                "date": self._extract_date(email_content),
                "reply_to": self._extract_reply_to(email_content)
            }
        }
        
        # Rule-based analysis
        domain = sender.split('@')[-1].lower() if '@' in sender else sender.lower()
        if domain in self.suspicious_domains:
            results["suspicious_sender"] = True
            results["score"] += 30
        
        # Extract links
        links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
        results["suspicious_links"] = links
        
        # KMP pattern matching for phishing keywords
        if self.trie.search(email_content):
            matched_keywords = self._get_matched_keywords(email_content)
            results["suspicious_content"].extend(matched_keywords)
            results["score"] += len(matched_keywords) * 5
        
        # Machine learning analysis if model is loaded
        if self.model:
            try:
                # Combine subject and body for prediction
                subject = results["email_analysis"]["subject"]
                combined_text = f"{subject} {email_content}" if subject else email_content
                
                # Get prediction probabilities
                proba = self.model.predict_proba([combined_text])[0]
                phishing_prob = proba[1]  # Probability of being phishing
                
                # Adjust score based on model confidence
                results["score"] += int(phishing_prob * 70)
                
                # Add ML prediction to results
                results["ml_prediction"] = {
                    "is_phishing": phishing_prob > 0.5,
                    "confidence": float(phishing_prob),
                    "version": "1.0"
                }
                
                # If model detects phishing but no keywords found
                if phishing_prob > 0.7 and not results["suspicious_content"]:
                    results["suspicious_content"].append(
                        "AI detected phishing patterns in email content"
                    )
            except Exception as e:
                logger.error(f"Model prediction failed: {str(e)}")
        
        # Normalize score and determine likelihood
        results["score"] = min(100, results["score"])
        results["likelihood"] = self._get_likelihood_level(results["score"])
        
        return results
    
    def _extract_subject(self, email_content: str) -> str:
        subject_match = re.search(r'Subject:([^\n]+)', email_content, re.IGNORECASE)
        return subject_match.group(1).strip() if subject_match else "No subject"
    
    def _extract_date(self, email_content: str) -> str:
        date_match = re.search(r'Date:([^\n]+)', email_content, re.IGNORECASE)
        return date_match.group(1).strip() if date_match else "No date"
    
    def _extract_reply_to(self, email_content: str) -> str:
        reply_match = re.search(r'Reply-To:([^\n]+)', email_content, re.IGNORECASE)
        return reply_match.group(1).strip() if reply_match else None
    
    def _get_matched_keywords(self, text: str) -> List[str]:
        matched = []
        text = text.lower()
        for keyword in self.common_phishing_keywords:
            if kmp_search(text, keyword):
                matched.append(keyword)
        return matched
    
    def _get_likelihood_level(self, score: float) -> str:
        if score >= 80:
            return "High"
        elif score >= 50:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Very Low"

class URLGraph:
    def __init__(self):
        self.graph = defaultdict(dict)
        self.node_features = {}
        self.suspicious_domains = set()
        self.visited = set()
    
    def add_url(self, url: str, features: Dict) -> None:
        parsed = urllib.parse.urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        
        if domain not in self.graph:
            self.graph[domain] = {}
            self.node_features[domain] = {
                "type": "domain",
                "suspicious": domain in self.suspicious_domains
            }
        
        if path and path != '/':
            path_node = domain + path
            if path_node not in self.graph:
                self.graph[path_node] = {}
                self.node_features[path_node] = {
                    "type": "path",
                    "suspicious": False
                }
            self.graph[domain][path_node] = 1
            self.graph[path_node][domain] = 1
    
    def add_suspicious_domain(self, domain: str) -> None:
        self.suspicious_domains.add(domain)
        if domain in self.node_features:
            self.node_features[domain]["suspicious"] = True
    
    def analyze_url(self, url: str) -> Dict:
        results = {
            "suspicious_domain": False,
            "suspicious_path": False,
            "has_connection": False,
            "connection_hops": 0,
            "score": 0
        }
        
        parsed = urllib.parse.urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        full_url = domain + path
        
        if domain in self.suspicious_domains:
            results["suspicious_domain"] = True
            results["score"] += 50
        
        if full_url in self.graph:
            # DFS to find connections to suspicious domains
            self.visited = set()
            min_distance = self._dfs(full_url, 0, float('inf'))
            
            if min_distance < float('inf'):
                results["has_connection"] = True
                results["connection_hops"] = min_distance
                results["score"] += max(0, 40 - min_distance * 5)
        
        return results
    
    def _dfs(self, current: str, depth: int, min_distance: int) -> int:
        if current in self.visited or depth > 5:
            return min_distance
        
        self.visited.add(current)
        
        if self.node_features.get(current, {}).get("suspicious", False):
            return min(depth, min_distance)
        
        for neighbor in self.graph[current]:
            min_distance = self._dfs(neighbor, depth + 1, min_distance)
        
        return min_distance
    
    def _is_similar_domain(self, domain1: str, domain2: str) -> bool:
        if domain1 == domain2:
            return True

        tlds = [".com", ".net", ".org", ".io", ".co"]
        d1 = domain1
        d2 = domain2
        for tld in tlds:
            d1 = d1.replace(tld, "")
            d2 = d2.replace(tld, "")
        
        if d1 in d2 or d2 in d1:
            return abs(len(d1) - len(d2)) <= 2
        
        return False

class PhishingDetector:
    def __init__(self, model_path: str = None):
        self.email_analyzer = EmailAnalyzer()
        self.url_graph = URLGraph()
        
        if model_path:
            self.email_analyzer.load_model(model_path)
        
        # Initialize domains
        self.legitimate_domains = set([
    # Educational
    "gehu.ac.in", "geu.ac.in", "harvard.edu", "mit.edu", "stanford.edu",
    "ox.ac.uk", "cambridge.ac.uk", "iitb.ac.in", "iitd.ac.in", "iitk.ac.in",
    
    # Tech Companies
    "google.com", "google.co.in", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "linkedin.com", "reddit.com", "wikipedia.org",
    "netflix.com", "spotify.com", "paypal.com", "adobe.com", "ibm.com",
    "intel.com", "nvidia.com", "oracle.com", "cisco.com", "dell.com",
    
    # Cloud Services
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com", "digitalocean.com",
    "heroku.com", "firebase.google.com", "vercel.com", "netlify.com",
    
    # Social Media
    "instagram.com", "pinterest.com", "tumblr.com", "flickr.com", "snapchat.com",
    "tiktok.com", "whatsapp.com", "telegram.org", "signal.org", "discord.com",
    
    # E-commerce
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "aliexpress.com",
    "flipkart.com", "myntra.com", "etsy.com", "shopify.com", "zomato.com",
    "swiggy.com", "ubereats.com", "doordash.com", "grubhub.com",
    
    # Financial
    "visa.com", "mastercard.com", "americanexpress.com", "discover.com",
    "jpmorgan.com", "bankofamerica.com", "wellsfargo.com", "chase.com",
    "citibank.com", "hsbc.com", "barclays.com", "standardchartered.com",
    
    # Government
    "usa.gov", "india.gov.in", "gov.uk", "canada.ca", "australia.gov.au",
    "gov.sg", "gov.za", "nz.govt.nz", "europa.eu", "un.org",
    
    # News
    "bbc.com", "cnn.com", "nytimes.com", "washingtonpost.com", "theguardian.com",
    "reuters.com", "aljazeera.com", "bloomberg.com", "economist.com", "wsj.com",
    
    # Email Providers
    "gmail.com", "outlook.com", "yahoo.com", "protonmail.com", "zoho.com",
    "mail.com", "aol.com", "icloud.com", "fastmail.com", "tutanota.com",
    
    # Open Source
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "apache.org",
    "gnu.org", "mozilla.org", "w3.org", "python.org", "kernel.org",
    
    # Streaming
    "youtube.com", "vimeo.com", "dailymotion.com", "twitch.tv", "disneyplus.com",
    "hulu.com", "hbomax.com", "peacocktv.com", "paramountplus.com", "sonyliv.com",
    
    # Productivity
    "office.com", "slack.com", "trello.com", "asana.com", "notion.so",
    "evernote.com", "dropbox.com", "box.com", "onedrive.live.com", "icloud.com",
    
    # Travel
    "booking.com", "expedia.com", "airbnb.com", "tripadvisor.com", "makemytrip.com",
    "kayak.com", "skyscanner.com", "agoda.com", "trivago.com", "cleartrip.com",
    
    # Health
    "who.int", "cdc.gov", "nih.gov", "mayoclinic.org", "webmd.com",
    "healthline.com", "medlineplus.gov", "apollo247.com", "practo.com", "1mg.com"
])
        
        self.suspicious_domains = set([
    # Generic phishing
    "phishingsite.com", "fake-login.com", "account-verify.com", "security-update.net",
    "password-reset.org", "login-now.com", "verify-account.com", "secure-login.net",
    
    # Brand impersonation
    "paypal-security.net", "appleid-verify.org", "bankofamerica.secure-login.com",
    "amazon-security.com", "ebay-secure.net", "netflix-payment.com", "google-account-security.com",
    "microsoft-verify.org", "facebook-security.net", "twitter-verify.org", 
    "instagram-login.com", "linkedin-secure.net", "whatsapp-verification.com",
    
    # Financial phishing
    "wellsfargo-secure.com", "chase-verify.net", "citibank-secure.org", 
    "hsbc-verification.com", "visa-payment.com", "mastercard-secure.net",
    "americanexpress-verify.com", "discover-security.org",
    
    # Government impersonation
    "irs-tax-refund.com", "socialsecurity-update.net", "medicare-verify.org",
    "usps-delivery.com", "fedex-tracking.net", "dhl-secure.com", "ups-verify.org",
    
    # Shipping scams
    "amazon-prime-gift.com", "flipkart-discount.net", "walmart-offer.com",
    "target-coupon.org", "ebay-deals.com", "aliexpress-promo.net",
    
    # Streaming scams
    "netflix-renewal.org", "hbo-max-payment.com", "disneyplus-verify.net", 
    "spotify-premium.com", "youtube-pro.net", "twitch-subscribe.com",
    
    # Tech support scams
    "microsoft-support.com", "apple-support.net", "google-help.org",
    "amazon-tech.com", "facebook-help.net", "twitter-support.org",
    
    # COVID scams
    "covid-vaccine.org", "pcr-test.net", "health-pass.com", 
    "vaccine-certificate.org", "covid-tracker.com",
    
    # Job scams
    "job-offer.net", "career-opportunity.com", "work-from-home.org",
    "high-salary-job.com", "immediate-hiring.net",
    
    # Lottery scams
    "you-won.com", "prize-claim.org", "lottery-winner.net",
    "congratulations-prize.com", "free-gift-card.org",
    
    # Crypto scams
    "bitcoin-giveaway.com", "ethereum-free.net", "crypto-invest.org",
    "wallet-verify.com", "coinbase-security.net"
])
        
        self._initialize_known_threats()
    
    def _initialize_known_threats(self) -> None:
        for domain in self.suspicious_domains:
            self.email_analyzer.add_suspicious_domain(domain)
            self.url_graph.add_suspicious_domain(f"https://{domain}")
    
    def analyze_email(self, email_content: str, sender: str) -> Dict:
        return self.email_analyzer.analyze_email(email_content, sender)
    
    def analyze_website(self, url: str) -> Dict:
        results = {
            "suspicious_domain": False,
            "suspicious_path": False,
            "has_connection": False,
            "connection_hops": 0,
            "score": 0,
            "security_issues": [],
            "domain_analysis": {
                "domain": "",
                "subdomain": "",
                "tld": "",
                "is_ip": False
            }
        }
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)
            
            # Domain analysis
            domain_name = f"{extracted.domain}.{extracted.suffix}"
            subdomain = extracted.subdomain
            
            results["domain_analysis"] = {
                "domain": domain_name,
                "subdomain": subdomain,
                "tld": extracted.suffix,
                "is_ip": bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_name))
            }
            
            # Check for IP address
            if results["domain_analysis"]["is_ip"]:
                results["security_issues"].append("Domain is an IP address")
                results["score"] += 40
            
            # Check for suspicious TLDs
            suspicious_tlds = {'xyz', 'top', 'loan', 'work', 'click', 'link', 'site'}
            if extracted.suffix in suspicious_tlds:
                results["security_issues"].append(f"Suspicious TLD: {extracted.suffix}")
                results["score"] += 30
            
            # Check for subdomain abuse
            if subdomain and len(subdomain.split('.')) > 2:
                results["security_issues"].append("Excessive subdomains")
                results["score"] += 20
            
            # Check for brand impersonation
            brand_domains = {
    # Tech Companies
    'google': ['gooogle', 'g00gle', 'gogle', 'googl3', 'goog1e', 'g00g1e', 'googIe', 'googie'],
    'microsoft': ['microsft', 'm1crosoft', 'micr0soft', 'rnicrosoft', 'micros0ft', 'micorsoft', 'm1cr0s0ft'],
    'apple': ['app1e', 'appie', 'appl3', 'aple', 'appie', 'app1eid', 'apleid'],
    'amazon': ['amaz0n', 'amazn', 'amaz0n', 'arnazon', 'amaz0nprime', 'amzon', 'amaz0npay'],
    'paypal': ['paypa1', 'paypall', 'paypa1', 'paypaI', 'paypa1verify', 'paypa1login', 'paypa1secure'],
    
    # Social Media
    'facebook': ['faceb00k', 'facebok', 'f4cebook', 'faceebook', 'facebo0k', 'facebook-login', 'facebook-secure'],
    'instagram': ['1nstagram', 'instagrarn', 'instagr4m', 'insta-gram', 'instagrarn-login', 'instagramverify'],
    'twitter': ['tw1tter', 'twiter', 'twitt3r', 'twitter-login', 'twitter-secure', 'twitterverify'],
    'linkedin': ['1inkedin', 'linked1n', 'linkdin', 'linkedin-login', 'linkedin-secure', 'linkedin-verify'],
    'whatsapp': ['whatsap', 'whatsappp', 'whatsapp-login', 'whatsapp-verify', 'whatsapp-secure'],
    
    # Financial Services
    'visa': ['visa-secure', 'visa-login', 'visa-verify', 'visa-payment', 'visa-support'],
    'mastercard': ['mastercard-secure', 'mastercard-login', 'mastercard-verify', 'mastercard-payment'],
    'americanexpress': ['americanexpress-login', 'americanexpress-verify', 'americanexpress-secure'],
    'westernunion': ['westernunion-payment', 'westernunion-transfer', 'westernunion-secure'],
    
    # E-commerce
    'ebay': ['ebay-login', 'ebay-secure', 'ebay-verify', 'ebay-payment', 'ebay-account'],
    'aliexpress': ['aliexpress-login', 'aliexpress-secure', 'aliexpress-verify', 'aliexpress-payment'],
    'walmart': ['walmart-login', 'walmart-secure', 'walmart-verify', 'walmart-payment'],
    'target': ['target-login', 'target-secure', 'target-verify', 'target-payment'],
    
    # Cloud Services
    'dropbox': ['dropbox-login', 'dropbox-secure', 'dropbox-verify', 'dropbox-share'],
    'adobe': ['adobe-login', 'adobe-secure', 'adobe-verify', 'adobe-cloud'],
    
    # Government/Taxes
    'irs': ['irs-tax', 'irs-refund', 'irs-payment', 'irs-login', 'irs-secure'],
    'socialsecurity': ['socialsecurity-login', 'socialsecurity-verify', 'socialsecurity-secure'],
    
    # Shipping
    'fedex': ['fedex-tracking', 'fedex-delivery', 'fedex-login', 'fedex-secure'],
    'ups': ['ups-tracking', 'ups-delivery', 'ups-login', 'ups-secure'],
    'dhl': ['dhl-tracking', 'dhl-delivery', 'dhl-login', 'dhl-secure'],
    
    # Streaming
    'netflix': ['netflix-login', 'netflix-secure', 'netflix-verify', 'netflix-payment'],
    'spotify': ['spotify-login', 'spotify-secure', 'spotify-verify', 'spotify-payment'],
    'hbo': ['hbo-login', 'hbo-secure', 'hbo-verify', 'hbo-payment'],
    
    # Crypto
    'coinbase': ['coinbase-login', 'coinbase-secure', 'coinbase-verify', 'coinbase-wallet'],
    'binance': ['binance-login', 'binance-secure', 'binance-verify', 'binance-wallet'],
    
    # Regional (India)
    'paytm': ['paytm-login', 'paytm-secure', 'paytm-verify', 'paytm-wallet'],
    'phonepe': ['phonepe-login', 'phonepe-secure', 'phonepe-verify', 'phonepe-wallet'],
    
    # Common Patterns
    'login': ['1ogin', 'log1n', 'Iogin', 'login-secure', 'login-verify'],
    'verify': ['ver1fy', 'verify-account', 'verify-now', 'verify-login'],
    'security': ['security-alert', 'security-update', 'security-verify', 'security-login']
}
            
            for brand, variations in brand_domains.items():
                if brand in domain_name.lower():
                    continue
                if any(kmp_search(domain_name.lower(), var) for var in variations):
                    results["security_issues"].append(f"Possible brand impersonation: {brand}")
                    results["score"] += 50
                    results["suspicious_domain"] = True
            
            # Check for URL obfuscation
            if self._is_obfuscated_url(url):
                results["security_issues"].append("URL contains obfuscation techniques")
                results["score"] += 35
            
            # Check for HTTPS
            if parsed.scheme != 'https':
                results["security_issues"].append("Not using HTTPS")
                results["score"] += 25
            
            # Check for suspicious paths
            suspicious_paths = [
    # Authentication-related
    'login', 'signin', 'sign-in', 'log-in', 'authenticate', 'auth',
    'authentication', 'verify', 'verification', 'validate', 'validation',
    'password', 'passwd', 'credential', 'security', 'secure',
    'session', 'sso', 'oauth', 'authorize', 'authorization',
    
    # Account-related
    'account', 'profile', 'user', 'member', 'myaccount', 'myprofile',
    'settings', 'preferences', 'dashboard', 'admin', 'administrator',
    'register', 'registration', 'signup', 'createaccount', 'activate',
    'activation', 'recover', 'recovery', 'reset', 'change', 'update',
    
    # Financial-related
    'payment', 'pay', 'checkout', 'billing', 'invoice', 'transaction',
    'transfer', 'withdraw', 'deposit', 'refund', 'subscribe', 'subscription',
    'donate', 'donation', 'purchase', 'order', 'cart', 'shopping',
    
    # Document-related
    'document', 'doc', 'file', 'attachment', 'view', 'download',
    'share', 'shared', 'preview', 'open', 'edit', 'upload',
    
    # Notification-related
    'alert', 'notification', 'message', 'inbox', 'mail', 'email',
    'announcement', 'reminder', 'warning', 'urgent', 'important',
    
    # Tech-support scams
    'support', 'help', 'contact', 'service', 'assistance', 'techsupport',
    'customer-service', 'customer-care', 'repair', 'fix', 'error',
    
    # Social engineering
    'offer', 'discount', 'deal', 'promo', 'promotion', 'bonus',
    'reward', 'gift', 'prize', 'win', 'winner', 'congratulations',
    'limited', 'exclusive', 'special', 'free', 'claim', 'apply',
    
    # Security-themed
    'unlock', 'lock', 'blocked', 'suspended', 'restricted', 'hacked',
    'compromised', 'breach', 'phishing', 'fraud', 'scam', 'virus',
    'malware', 'antivirus', 'scan', 'protection', 'privacy',
    
    # Government/legal-themed
    'irs', 'tax', 'refund', 'socialsecurity', 'medicare', 'legal',
    'court', 'law', 'police', 'fbi', 'government', 'official',
    
    # Shipping-themed
    'tracking', 'delivery', 'shipment', 'package', 'post', 'mail',
    'courier', 'dispatch', 'orderstatus', 'shipping', 'address',
    
    # COVID-related
    'covid', 'corona', 'vaccine', 'vaccination', 'certificate',
    'test', 'result', 'health', 'pass', 'pandemic',
    
    # Job-related scams
    'career', 'job', 'opportunity', 'hiring', 'recruit', 'recruitment',
    'interview', 'resume', 'application', 'applynow', 'workfromhome',
    
    # Crypto scams
    'wallet', 'crypto', 'bitcoin', 'ethereum', 'nft', 'token',
    'airdrop', 'mining', 'exchange', 'blockchain', 'metamask',
    
    # Regional variants
    'iniciar-sesion', 'connexion', 'anmelden', 'accesso', 'ログイン', '登录'
]
            if any(kmp_search(parsed.path.lower(), pattern) for pattern in suspicious_paths):
                results["suspicious_path"] = True
                results["score"] += 15
            
            # Check known domains
            if domain_name in self.suspicious_domains and domain_name not in self.legitimate_domains:
                results["suspicious_domain"] = True
                results["score"] += 60
                results["security_issues"].append("Known suspicious domain")
            
            # Check URL graph connections
            if domain_name not in self.legitimate_domains:
                url_result = self.url_graph.analyze_url(url)
                if url_result["has_connection"]:
                    results["has_connection"] = True
                    results["connection_hops"] = url_result["connection_hops"]
                    results["score"] += url_result["score"]
            
            # Normalize score
            results["score"] = min(100, results["score"])
            results["likelihood"] = self._get_likelihood_level(results["score"])
            
            return results
            
        except Exception as e:
            results["security_issues"].append(f"Error analyzing URL: {str(e)}")
            results["score"] = 100
            results["likelihood"] = "High"
            return results
    
    def _get_likelihood_level(self, score: float) -> str:
        if score >= 80:
            return "High"
        elif score >= 50:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Very Low"
    
    def _is_obfuscated_url(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                return True
            
            if parsed.netloc.count('.') > 3:
                return True
            
            if '%' in parsed.netloc or '%' in parsed.path:
                return True
            
            if any(c.isupper() for c in parsed.netloc) and any(c.islower() for c in parsed.netloc):
                return True
            
            suspicious_chars = ['-', '_', '~', '!', '*', "'", '(', ')', ';', ':', '@', '&', '=', '+', '$', ',', '/', '?', '#', '[', ']']
            if any(char in parsed.netloc for char in suspicious_chars):
                return True
            
            if len(parsed.netloc) > 50:
                return True
            
            return False
            
        except Exception:
            return True