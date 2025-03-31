import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"  # Disable oneDNN optimizations

import re
import socket
import ssl
import urllib.parse
import requests
from datetime import datetime
import whois
import tldextract
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import tensorflow as tf
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import track
from functools import lru_cache
from bs4 import BeautifulSoup  # For HTML parsing

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()

# Set TensorFlow log level
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

class WebsiteSecurityAnalyzer:
    def __init__(self, use_ml=True):
        self.use_ml = use_ml
        self.console = console
        self.executor = ThreadPoolExecutor(max_workers=5)
        # Known malicious URL patterns
        self.suspicious_patterns = [
            r'login.*\.php',
            r'secure.*\.php',
            r'account.*\.php',
            r'admin.*\.php',
            r'bank.*\.php',
            r'update.*\.php',
            r'wp-includes',
            r'download.*\.php',
            r'\.exe$',
            r'(bitcoin|btc|crypto|wallet|blockchain)',
            r'(free.*money|prize|winner)',
            r'password.*reset',
        ]
        # Additional HTML/JS patterns (for demonstration)
        self.malicious_html_patterns = [
            r'<script>.*eval\(.*\)</script>',
            r'<script>.*document\.write\(.*\)</script>',
            r'<!--\s*malicious\s*-->',
        ]
        # Suspicious TLDs
        self.suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf']
        # Reputable domains (bonus: lower risk if found)
        self.reputable_domains = [
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'youtube.com'
        ]
        
        if self.use_ml:
            self.model_file = "tf_malicious_model.h5"
            if os.path.exists(self.model_file):
                self.ml_model = tf.keras.models.load_model(self.model_file)
                logging.info(f"Loaded existing TensorFlow model from {self.model_file}")
            else:
                logging.info("No existing model found. Training a new TensorFlow model with sample data.")
                self.ml_model = self._train_initial_model_tf()
                self.ml_model.save(self.model_file)
                logging.info(f"Saved new TensorFlow model to {self.model_file}")

    def _train_initial_model_tf(self):
        X = np.array([
            [1, 0, 3650, 0, 10, 0, 0, 1, 30],
            [1, 0, 5840, 0, 12, 0, 0, 1, 32],
            [1, 0, 2190, 0, 15, 0, 0, 2, 45],
            [1, 0, 4380, 0, 11, 0, 0, 1, 29],
            [1, 0, 1825, 0, 14, 0, 0, 3, 50],
            [1, 0, 3000, 0, 13, 0, 0, 1, 33],
            [1, 0, 2738, 0, 12, 0, 0, 2, 38],
            [1, 0, 4100, 0, 11, 0, 0, 1, 31],
            [1, 1, 1800, 0, 16, 0, 0, 2, 42],
            [1, 0, 2500, 0, 14, 0, 0, 1, 35],
            [0, 3, 2, 1, 35, 0, 1, 3, 120],
            [0, 2, 5, 0, 40, 1, 1, 0, 80],
            [0, 4, 10, 1, 45, 0, 1, 4, 130],
            [0, 3, 15, 1, 28, 0, 1, 2, 90],
            [1, 2, 20, 0, 50, 0, 1, 3, 100],
            [0, 5, 3, 1, 55, 0, 0, 5, 140],
            [0, 2, 8, 1, 30, 1, 1, 0, 70],
            [0, 3, 12, 1, 25, 0, 1, 2, 85],
            [0, 4, 5, 0, 42, 0, 1, 3, 110],
            [1, 3, 7, 1, 38, 0, 1, 4, 95],
        ], dtype='float32')
        y = np.array([0]*10 + [1]*10, dtype='float32')
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(16, activation='relu', input_shape=(9,)),
            tf.keras.layers.Dense(8, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        model.fit(X, y, epochs=50, verbose=0)
        return model

    def analyze_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        full_path = parsed_url.path
        ext = tldextract.extract(domain)
        base_domain = f"{ext.domain}.{ext.suffix}"
        tld = f".{ext.suffix}"

        results = {
            'url': url,
            'domain': domain,
            'checks': {},
            'heuristic_scores': {},  # individual scores out of 10
            'heuristic_average': 0,
            'risk_score': 0,
            'risk_level': '',
            'details': [],
            'ml_prediction': None,
            'feature_importances': {}
        }

        # Run asynchronous checks
        futures = {
            self.executor.submit(self._check_redirects_chain, url, results): 'redirect_chain',
            self.executor.submit(self._check_domain_age, domain, results): 'domain_age',
            self.executor.submit(self._check_ssl_certificate, domain, results): 'ssl',
            self.executor.submit(self._check_html_content, url, results): 'html'
        }
        # Run synchronous checks
        self._check_https(url, results)
        self._check_suspicious_patterns(url, full_path, results)
        self._check_suspicious_tld(tld, results)
        self._check_domain_reputation(base_domain, results)
        self._check_domain_length(domain, results)
        self._check_ip_url(domain, results)
        self._check_owasp_vulnerabilities(url, results)
        # Wait for async checks
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error in asynchronous check {futures[future]}: {e}")

        # Compute overall heuristic average (out of 10)
        # Only include checks that were added to results['heuristic_scores']
        scores = list(results.get('heuristic_scores', {}).values())
        if scores:
            avg = sum(scores) / len(scores)
        else:
            avg = 0
        results['heuristic_average'] = round(avg, 2)

        # ML prediction: 10 if malicious, 0 if benign
        if self.use_ml:
            ml_result = self._ml_prediction(url, results)
            results['ml_prediction'] = ml_result['prediction']
            results['feature_importances'] = ml_result['feature_importances']
            ml_score = 10 if ml_result['prediction'] == 1 else 0
        else:
            ml_score = 0

        # Final risk score: blend heuristic (30%) and ML (70%) on a 0–10 scale
        final_score = 0.3 * results['heuristic_average'] + 0.7 * ml_score
        results['risk_score'] = round(final_score, 2)

        # Set risk level based on final score
        if results['risk_score'] >= 7:
            results['risk_level'] = 'High Risk'
        elif results['risk_score'] >= 4:
            results['risk_level'] = 'Medium Risk'
        else:
            results['risk_level'] = 'Low Risk'

        self._visualize_checks(results['heuristic_scores'])
        return results

    def _ml_prediction(self, url, results):
        features = self._extract_features(url, results)
        features = np.array(features, dtype='float32').reshape(1, -1)
        prediction_prob = self.ml_model.predict(features)[0][0]
        prediction = 1 if prediction_prob >= 0.5 else 0
        dummy_importances = {
            'uses_https': 0.15,
            'suspicious_patterns_count': 0.20,
            'domain_age_days': 0.10,
            'uses_suspicious_tld': 0.15,
            'domain_length': 0.10,
            'uses_ip': 0.05,
            'redirects': 0.10,
            'subdomains_count': 0.05,
            'url_length': 0.10
        }
        if prediction == 1:
            results['details'].append("TensorFlow model flagged this URL as potentially malicious.")
            top_features = sorted(dummy_importances.items(), key=lambda x: x[1], reverse=True)[:3]
            for feature, importance in top_features:
                results['details'].append(f"Important factor: {feature.replace('_', ' ')} (importance: {importance:.2f})")
        return {'prediction': prediction, 'feature_importances': dummy_importances}

    def _extract_features(self, url, results):
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        ext = tldextract.extract(domain)
        tld = f".{ext.suffix}"
        suspicious_pattern_count = sum(1 for pattern in self.suspicious_patterns if re.search(pattern, url, re.IGNORECASE))
        subdomain_count = len(domain.split('.')) - 2 if domain.count('.') > 0 else 0
        domain_age = results.get('heuristic_scores', {}).get('domain_age', 0)
        redirect_chain = results.get('heuristic_scores', {}).get('redirect_chain', 0)
        features = [
            1 if url.startswith('https://') else 0,
            suspicious_pattern_count,
            domain_age,
            1 if tld in self.suspicious_tlds else 0,
            len(domain),
            1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0,
            redirect_chain,
            subdomain_count,
            len(url)
        ]
        return features

    def _check_https(self, url, results):
        score = 0 if url.startswith('https://') else 10
        results.setdefault('heuristic_scores', {})['https'] = score
        if score == 10:
            results['details'].append("Website does not use HTTPS encryption.")

    def _check_suspicious_patterns(self, url, path, results):
        # Each match adds 3 points, cap at 10; extra +2 if too many subdomains; extra +2 if URL too long
        matches = sum(1 for pattern in self.suspicious_patterns if re.search(pattern, url, re.IGNORECASE))
        score = min(matches * 3, 10)
        subdomain_count = len(url.split('.')) - 2
        if subdomain_count > 3:
            score = min(score + 2, 10)
            results['details'].append(f"URL contains excessive subdomains ({subdomain_count}).")
        if len(url) > 100:
            score = min(score + 2, 10)
            results['details'].append(f"Unusually long URL ({len(url)} characters).")
        results.setdefault('heuristic_scores', {})['patterns'] = score

    def _check_domain_age(self, domain, results):
        whois_info = self._whois_lookup(domain)
        try:
            creation_date = whois_info.creation_date if whois_info else None
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
                if domain_age_days < 30:
                    score = 10
                    results['details'].append(f"Domain is very new ({domain_age_days} days old).")
                elif domain_age_days < 90:
                    score = 5
                    results['details'].append(f"Domain is relatively new ({domain_age_days} days old).")
                else:
                    score = 0
                results.setdefault('heuristic_scores', {})['domain_age'] = score
            else:
                results.setdefault('heuristic_scores', {})['domain_age'] = 5
                results['details'].append("Unable to determine domain age.")
        except Exception:
            results.setdefault('heuristic_scores', {})['domain_age'] = 5
            results['details'].append("Unable to verify domain registration information.")

    def _check_suspicious_tld(self, tld, results):
        score = 10 if tld in self.suspicious_tlds else 0
        results.setdefault('heuristic_scores', {})['tld'] = score
        if score == 10:
            results['details'].append(f"Domain uses suspicious TLD: {tld}.")

    def _check_domain_reputation(self, domain, results):
        # Good reputation subtracts 10 (bonus), else 0.
        score = -10 if domain in self.reputable_domains else 0
        results.setdefault('heuristic_scores', {})['reputation'] = score
        if score < 0:
            results['details'].append("Domain has good reputation.")

    def _check_domain_length(self, domain, results):
        score = 10 if len(domain) > 30 else 0
        results.setdefault('heuristic_scores', {})['domain_length'] = score
        if score:
            results['details'].append(f"Unusually long domain name ({len(domain)} characters).")

    def _check_ip_url(self, domain, results):
        score = 10 if re.match(r'^(\d{1,3}(\.\d{1,3}){3})$', domain) else 0
        results.setdefault('heuristic_scores', {})['ip_url'] = score
        if score:
            results['details'].append("URL uses an IP address instead of a domain name.")

    def _check_redirects_chain(self, url, results):
        try:
            response = requests.get(url, allow_redirects=True, timeout=5)
            chain_length = len(response.history)
            # Each redirect adds 2 points; if final domain is different add extra 2; cap at 10.
            score = min(chain_length * 2, 10)
            final_domain = urllib.parse.urlparse(response.url).netloc
            if final_domain not in url:
                score = min(score + 2, 10)
                results['details'].append(f"Final redirect domain ({final_domain}) differs from original.")
            results.setdefault('heuristic_scores', {})['redirect_chain'] = score
            results['details'].append(f"Redirect chain length: {chain_length}.")
        except Exception:
            results.setdefault('heuristic_scores', {})['redirect_chain'] = 5
            results['details'].append("Unable to fully follow redirect chain.")

    def _check_ssl_certificate(self, domain, results):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    exp_str = cert['notAfter']
                    exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    score = 0 if exp_date > datetime.now() else 10
                    if score:
                        results['details'].append("SSL certificate is expired.")
                    else:
                        results['details'].append("SSL certificate is valid.")
            results.setdefault('heuristic_scores', {})['ssl'] = score
        except Exception as e:
            results.setdefault('heuristic_scores', {})['ssl'] = 10
            results['details'].append("Unable to verify SSL certificate.")

    def _check_html_content(self, url, results):
        try:
            response = requests.get(url, timeout=5)
            content = response.text
            score = 0
            for pattern in self.malicious_html_patterns:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    score += 3
                    results['details'].append(f"Suspicious HTML/JS pattern detected: {pattern}")
            results.setdefault('heuristic_scores', {})['html'] = min(score, 10)
        except Exception:
            results.setdefault('heuristic_scores', {})['html'] = 5
            results['details'].append("Unable to fetch or analyze HTML content.")

    def _check_owasp_vulnerabilities(self, url, results):
        owasp_keywords = {
            'injection': ['select', 'drop', 'insert', 'update', "' or", '" or'],
            'xss': ['<script>', 'javascript:'],
            'sensitive_data_exposure': ['password', 'ssn', 'creditcard'],
            'security_misconfiguration': ['.env', 'config']
        }
        score = 0
        for vuln, keywords in owasp_keywords.items():
            for keyword in keywords:
                if keyword.lower() in url.lower():
                    score += 5
                    results['details'].append(f"URL may be prone to {vuln} vulnerability (found: {keyword}).")
                    break
        owasp_api_score = self._simulate_owasp_api_call(url)
        score = min(score + owasp_api_score, 10)
        results.setdefault('heuristic_scores', {})['owasp'] = score

    def _simulate_owasp_api_call(self, url):
        return 5 if "admin" in url.lower() else 0

    @lru_cache(maxsize=50)
    def _whois_lookup(self, domain):
        try:
            return whois.whois(domain)
        except Exception as e:
            logging.error(f"WHOIS lookup failed for {domain}: {e}")
            return None

    def _visualize_checks(self, heuristic_scores):
        df = pd.DataFrame(list(heuristic_scores.items()), columns=['Check', 'Score'])
        console.print("\n[bold green]Heuristic Checks Breakdown:[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Check")
        table.add_column("Score", justify="right")
        for check, score in heuristic_scores.items():
            table.add_row(check, str(score))
        console.print(table)
        plt.figure(figsize=(10, 5))
        plt.bar(df['Check'], df['Score'], color='cornflowerblue')
        plt.xlabel('Security Checks')
        plt.ylabel('Score (out of 10)')
        plt.title('Heuristic Security Checks Breakdown')
        plt.tight_layout()
        plt.savefig("heuristic_scores.png")
        plt.close()
        console.print("[bold yellow]Bar chart saved as 'heuristic_scores.png'.[/bold yellow]")

    def retrain_model(self, urls_with_labels):
        if not self.use_ml:
            console.print("[red]ML functionality is disabled[/red]")
            return False
        try:
            X, y = [], []
            for url, label in track(urls_with_labels, description="Retraining model..."):
                results = self.analyze_url(url)
                features = self._extract_features(url, results)
                X.append(features)
                y.append(label)
            X = np.array(X, dtype='float32')
            y = np.array(y, dtype='float32')
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(16, activation='relu', input_shape=(9,)),
                tf.keras.layers.Dense(8, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            model.fit(X, y, epochs=50, verbose=0)
            self.ml_model = model
            self.ml_model.save(self.model_file)
            console.print(f"[bold green]Model retrained with {len(urls_with_labels)} examples.[/bold green]")
            return True
        except Exception as e:
            console.print(f"[red]Error retraining model: {e}[/red]")
            return False

def run_cli(args):
    analyzer = WebsiteSecurityAnalyzer(use_ml=True)
    if args.url:
        for url in args.url:
            console.print(f"\n[cyan]Analyzing URL: {url}[/cyan]")
            results = analyzer.analyze_url(url)
            display_results(results)
    else:
        while True:
            console.print("\n[bold cyan]Options:[/bold cyan]")
            console.print("1. Analyze a URL")
            console.print("2. Provide feedback on URL (improve ML model)")
            console.print("3. Exit")
            choice = input("\nEnter your choice (1-3): ")
            if choice == '1':
                url = input("\nEnter a URL to analyze: ")
                results = analyzer.analyze_url(url)
                display_results(results)
            elif choice == '2':
                url = input("\nEnter the URL to provide feedback on: ")
                while True:
                    label_input = input("Is this URL malicious? (y/n): ").lower()
                    if label_input in ['y', 'n']:
                        break
                    console.print("Please enter 'y' or 'n'")
                label = 1 if label_input == 'y' else 0
                analyzer.retrain_model([(url, label)])
            elif choice == '3':
                console.print("\nExiting. Thank you for using the advanced Website Security Analyzer!")
                break
            else:
                console.print("\n[red]Invalid choice. Please enter 1, 2, or 3.[/red]")

def display_results(results):
    console.print("\n[bold magenta]═══════════════════════════════════════════════[/bold magenta]")
    console.print(f"[bold]ANALYSIS RESULTS FOR:[/bold] {results['url']}")
    console.print("[bold magenta]═══════════════════════════════════════════════[/bold magenta]")
    console.print(f"[bold]RISK SCORE:[/bold] {results['risk_score']}/10")
    console.print(f"[bold]RISK LEVEL:[/bold] {results['risk_level']}")
    if results.get('ml_prediction') is not None:
        ml_str = "Malicious" if results['ml_prediction'] == 1 else "Benign"
        console.print(f"[bold]ML PREDICTION:[/bold] {ml_str}")
    console.print("[bold]DETAILS:[/bold]")
    if results['details']:
        for detail in results['details']:
            console.print(f"• {detail}")
    else:
        console.print("• No specific security issues detected")
    console.print("[bold magenta]═══════════════════════════════════════════════[/bold magenta]\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced CLI Website Security Analyzer (Scores out of 10)")
    parser.add_argument("--url", nargs="*", help="Provide one or more URLs to analyze in batch mode")
    args = parser.parse_args()
    run_cli(args)
