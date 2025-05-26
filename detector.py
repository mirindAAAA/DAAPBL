import re
from collections import defaultdict
import heapq
import urllib.parse
import tldextract
from typing import List, Dict, Set, Optional

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
            "account", "update", "confirm", "dear customer", "unauthorized access", "account verification", "password reset", "security update",
    "billing information", "credit card", "social security", "account suspension",
    "verify your identity", "important notice", "immediate attention", "account closure",
    "fraud alert", "suspicious activity", "unusual login attempt", "account restricted",
    "payment failed", "invoice attached", "order confirmation", "shipping notification",
    "document shared", "secure message", "account compromised", "locked out",
    "temporary hold", "expiration notice", "renew now", "last chance",
    "exclusive offer", "congratulations", "claim your prize", "you've been selected",
    "limited offer", "act now", "don't miss out", "final warning",
    "account deactivation", "verify now", "click below", "secure your account",
    "urgent review", "take action", "response required", "attention required"
        ]
        self.suspicious_domains = set()
        
        for keyword in self.common_phishing_keywords:
            self.trie.insert(keyword)
    
    def add_suspicious_domain(self, domain: str) -> None:
        self.suspicious_domains.add(domain.lower())
    
    def analyze_email(self, email_content: str, sender: str) -> Dict:
        results = {
            "suspicious_keywords": [],
            "suspicious_sender": False,
            "links": [],
            "score": 0
        }
        
        domain = sender.split('@')[-1].lower() if '@' in sender else sender.lower()
        if domain in self.suspicious_domains:
            results["suspicious_sender"] = True
            results["score"] += 30
        
        links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
        results["links"] = links
        
        if self.trie.search(email_content):
            results["suspicious_keywords"] = self._get_matched_keywords(email_content)
            results["score"] += len(results["suspicious_keywords"]) * 5
        
        urgency_patterns = ["immediate action", "within 24 hours", "urgent", "right away"]
        for pattern in urgency_patterns:
            if kmp_search(email_content, pattern):
                results["score"] += 10
                if pattern not in results["suspicious_keywords"]:
                    results["suspicious_keywords"].append(pattern)
        
        return results
    
    def _get_matched_keywords(self, text: str) -> List[str]:
        matched = []
        text = text.lower()
        for keyword in self.common_phishing_keywords:
            if kmp_search(text, keyword):
                matched.append(keyword)
        return matched

class URLGraph:
    def __init__(self):
        self.graph = defaultdict(dict)
        self.node_features = {}
        self.suspicious_domains = set()
    
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
            "distance_to_suspicious": float('inf'),
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
            shortest_path = self.dijkstra(full_url)
            
            min_distance = float('inf')
            for node, dist in shortest_path.items():
                if self.node_features.get(node, {}).get("suspicious", False):
                    if dist < min_distance:
                        min_distance = dist
            
            results["distance_to_suspicious"] = min_distance
            results["score"] += max(0, 30 - min_distance * 5)
        
        extracted = tldextract.extract(url)
        domain_name = f"{extracted.domain}.{extracted.suffix}"
        
        for suspicious_domain in self.suspicious_domains:
            if self._is_similar_domain(domain_name, suspicious_domain):
                results["suspicious_domain"] = True
                results["score"] += 40
                break
        
        return results
    
    def dijkstra(self, start: str) -> Dict[str, float]:
        distances = {node: float('inf') for node in self.graph}
        distances[start] = 0
        heap = [(0, start)]
        
        while heap:
            current_dist, current_node = heapq.heappop(heap)
            
            if current_dist > distances[current_node]:
                continue
            
            for neighbor, weight in self.graph[current_node].items():
                distance = current_dist + weight
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    heapq.heappush(heap, (distance, neighbor))
        
        return distances
    
    def _is_similar_domain(self, domain1: str, domain2: str) -> bool:
        # Only consider as similar if they are not exactly the same and
        # the suspicious domain is a subdomain or a very close typo
        if domain1 == domain2:
            return True

        # Remove TLDs for comparison
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
    def __init__(self):
        self.email_analyzer = EmailAnalyzer()
        self.url_graph = URLGraph()
        self.legitimate_domains = set([
            "gehu.ac.in","geu.ac.in","google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com", "linkedin.com", "wikipedia.org", "amazon.com", "reddit.com", "netflix.com", "microsoft.com", "apple.com", "spotify.com", "paypal.com", "adobe.com", "dropbox.com", "github.com", "medium.com", "quora.com", "stackoverflow.com", "bing.com", "yahoo.com", "cnn.com", "nytimes.com", "bbc.com", "aljazeera.com", "bloomberg.com", "forbes.com", "reuters.com", "theguardian.com", "nbcnews.com", "usatoday.com", "washingtonpost.com", "cbsnews.com", "abcnews.go.com", "foxnews.com", "time.com", "wsj.com", "vice.com", "politico.com", "techcrunch.com", "wired.com", "theverge.com", "mashable.com", "gizmodo.com", "lifehacker.com", "engadget.com", "cnet.com", "zdnet.com", "pcmag.com", "digitaltrends.com", "android.com", "wordpress.com", "wix.com", "squarespace.com", "godaddy.com", "bluehost.com", "hostgator.com", "siteground.com", "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", "digitalocean.com", "heroku.com", "mongodb.com", "firebase.google.com", "vercel.com", "netlify.com", "stripe.com", "squareup.com", "shopify.com", "etsy.com", "ebay.com", "walmart.com", "costco.com", "target.com", "bestbuy.com", "homedepot.com", "lowes.com", "ikea.com", "nike.com", "adidas.com", "puma.com", "reebok.com", "underarmour.com", "patagonia.com", "northface.com", "columbia.com", "levis.com", "gap.com", "oldnavy.com", "uniqlo.com", "zara.com", "hm.com", "macys.com", "nordstrom.com", "bloomingdales.com", "saksfifthavenue.com", "neimanmarcus.com", "jcrew.com"
        ])
        self.suspicious_domains = set([
            "phishingsite.com", "fake-login.com", "paypal-security.net", "appleid-verify.org", "bankofamerica.secure-login.com","amazon-security.com", "ebay-secure.net", "netflix-payment.com", "microsoft-verify.org", "google-account-security.com", "wellsfargo-secure.com", "chase-verify.net", "bankofamerica-login.com", "citibank-secure.org", "hsbc-verification.com", "facebook-security.net", "twitter-verify.org", "instagram-login.com", "linkedin-secure.net", "whatsapp-verification.com", "dropbox-security.org", "onedrive-verify.com", "icloud-secure.net", "adobe-account.com", "spotify-payment.org", "paypal-secure-login.com", "venmo-verify.net", "cashapp-security.com", "coinbase-verification.org", "binance-secure.com", "irs-tax-refund.com", "socialsecurity-update.net", "medicare-verify.org", "usps-delivery.com", "fedex-tracking.net", "amazon-prime-gift.com", "netflix-renewal.org", "hbo-max-payment.com", "disneyplus-verify.net", "spotify-premium.com"
        ])
        self._initialize_known_threats()
    
    def _initialize_known_threats(self) -> None:
        for domain in self.suspicious_domains:
            self.email_analyzer.add_suspicious_domain(domain)
            self.url_graph.add_suspicious_domain(f"https://{domain}")
    
    def analyze_email(self, email_content: str, sender: str) -> Dict:
        email_results = self.email_analyzer.analyze_email(email_content, sender)
        
        link_scores = []
        for link in email_results["links"]:
            url_result = self.analyze_website(link)
            link_scores.append(url_result["score"])
        
        if link_scores:
            max_link_score = max(link_scores)
            email_results["score"] += max_link_score * 0.7
        
        email_results["likelihood"] = self._get_likelihood_level(email_results["score"])
        
        return email_results
    
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
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)
            
            # Basic domain analysis
            domain_name = f"{extracted.domain}.{extracted.suffix}"
            subdomain = extracted.subdomain
            
            results["domain_analysis"] = {
                "domain": domain_name,
                "subdomain": subdomain,
                "tld": extracted.suffix,
                "is_ip": bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_name))
            }
            
            # Check for IP address in domain
            if results["domain_analysis"]["is_ip"]:
                results["security_issues"].append("Domain is an IP address")
                results["score"] += 40
            
            # Check for suspicious TLDs
            suspicious_tlds = {'xyz', 'top', 'loan', 'work', 'click', 'link', 'site', 'online', 'space', 'website'}
            if extracted.suffix in suspicious_tlds:
                results["security_issues"].append(f"Suspicious TLD: {extracted.suffix}")
                results["score"] += 30
            
            # Check for subdomain abuse
            if subdomain and len(subdomain.split('.')) > 2:
                results["security_issues"].append("Excessive subdomains")
                results["score"] += 20
            
            # Check for domain similarity with known brands
            brand_domains = {
                'google': ['gooogle', 'g00gle', 'gogle'],
                'microsoft': ['microsft', 'm1crosoft', 'micr0soft'],
                'apple': ['app1e', 'appie', 'appl3'],
                'amazon': ['amaz0n', 'amazn', 'amaz0n'],
                'paypal': ['paypa1', 'paypall', 'paypa1'],
                'facebook': ['faceb00k', 'facebok', 'f4cebook'],
                'netflix': ['netfl1x', 'netflx', 'n3tflix']
            }
            
            for brand, variations in brand_domains.items():
                # Do not flag the real brand domain
                if brand in domain_name.lower():
                    continue
                if any(var in domain_name.lower() for var in variations):
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
            
            # Check for suspicious path patterns
            suspicious_paths = ['login', 'signin', 'account', 'verify', 'secure', 'auth', 'password']
            if any(pattern in parsed.path.lower() for pattern in suspicious_paths):
                results["suspicious_path"] = True
                results["score"] += 15
            
            # Check for known suspicious domains (exact match, not similar, and not legitimate)
            if domain_name in self.suspicious_domains and domain_name not in self.legitimate_domains:
                results["suspicious_domain"] = True
                results["score"] += 60
                results["security_issues"].append("Known suspicious domain")
            
            # Check for connection to known phishing sites (similar domains, but not legitimate)
            if domain_name not in self.legitimate_domains:
                for suspicious_domain in self.suspicious_domains:
                    if self._is_similar_domain(domain_name, suspicious_domain):
                        results["has_connection"] = True
                        results["connection_hops"] = 1
                        break
            
            # Normalize score to 0-100 range
            results["score"] = min(100, results["score"])
            
            # Add likelihood level
            results["likelihood"] = self._get_likelihood_level(results["score"])
            
            return results
            
        except Exception as e:
            results["security_issues"].append(f"Error analyzing URL: {str(e)}")
            results["score"] = 100  # Mark as highly suspicious if analysis fails
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
    
    def _check_login_form(self, url: str) -> bool:
        return bool(re.search(r"login|signin|auth|password", url.lower()))
    
    def _is_obfuscated_url(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check for IP address in domain
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                return True
            
            # Check for excessive dots
            if parsed.netloc.count('.') > 3:
                return True
            
            # Check for URL encoding
            if '%' in parsed.netloc or '%' in parsed.path:
                return True
            
            # Check for mixed case in domain
            if any(c.isupper() for c in parsed.netloc) and any(c.islower() for c in parsed.netloc):
                return True
            
            # Check for suspicious characters
            suspicious_chars = ['-', '_', '~', '!', '*', "'", '(', ')', ';', ':', '@', '&', '=', '+', '$', ',', '/', '?', '#', '[', ']']
            if any(char in parsed.netloc for char in suspicious_chars):
                return True
            
            # Check for excessive length
            if len(parsed.netloc) > 50:
                return True
            
            return False
            
        except Exception:
            return True  # If we can't parse the URL, consider it suspicious

detector = PhishingDetector()
results = detector.analyze_website("suspicious-url.com")



