# WebsiteSecurity Analyzer 2.0

Welcome to the Advanced Website Security Analyzer! This is a friendly, Python-based tool designed to help you quickly assess the security of websites. By combining tried-and-true heuristic checks with a smart machine learning model, this tool helps you spot potentially malicious websites before they can cause trouble.

## What It Does

- **Heuristic Security Checks**
  - **HTTPS Check:** Quickly tells you if the website is using secure HTTPS.
  - **Suspicious Patterns:** Scans the URL for red flags like common malicious patterns and keywords.
  - **Domain Age Analysis:** Looks up the domain's age using WHOIS data to see if it's a new, and potentially risky, site.
  - **SSL Certificate Validation:** Checks if the site's SSL certificate is valid.
  - **HTML Content Analysis:** Scans the website’s code for any suspicious HTML or JavaScript.
  - **OWASP Vulnerability Checks:** Simulates tests for common web vulnerabilities like SQL injection or XSS.

- **Machine Learning Magic**
  - Uses a TensorFlow model that has been trained on real-world examples to predict if a URL might be malicious.
  - Combines the ML prediction with heuristic scores to give you an overall risk rating.
  - Offers insights on which factors influenced the ML prediction the most.

- **Performance & Visual Insights**
  - Runs several checks at once for faster results.
  - Creates a neat bar chart (`heuristic_scores.png`) to show you the scores for each security check.
  - Features an interactive CLI built with the Rich library, making the tool both fun and easy to use.

- **Continuous Learning**
  - You can provide feedback on the analysis results, which helps retrain and improve the machine learning model over time.

## Getting Started

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/WebsiteSecurityAnalzyer-2.0.git
   cd WebsiteSecurityAnalzyer-2.0`
   
2. **Install the Required Libraries:**
   ```bash
   pip install tensorflow requests python-whois tldextract numpy pandas matplotlib beautifulsoup4 rich

You'll need packages like TensorFlow, Requests, WHOIS, tldextract, NumPy, Pandas, Matplotlib, BeautifulSoup4, and Rich.

3.**Optional Configuration:**
The tool disables oneDNN optimizations for TensorFlow by setting:

```bash
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
```
## How To Use

**Interactive Mode**
Just run the tool without any arguments, and you'll enter an easy-to-use interactive menu:
```bash
python security_analzyer_3.py
```
You can choose to:

Analyze a URL

Provide feedback to help improve the model

Exit the tool

**What the Output Looks Like**
**Risk Score:** A final score out of 10 that tells you how risky the website might be.

**Risk Level:** Categorized as Low, Medium, or High Risk.

**Details:** A clear breakdown of what was checked and why.

**Visualization:** A bar chart (heuristic_scores.png) that visualizes the scores from each security check.

## Inside the Code
**Main Class:**
The WebsiteSecurityAnalyzer class is the heart of the tool. It handles all the security checks and ML predictions.

**Security Checks:**
Each security check (like HTTPS verification or SSL certificate validation) is done by its own function, making the code modular and easy to understand.

**Machine Learning:**
The tool trains a TensorFlow model to help predict if a URL is malicious. It can also be retrained with your feedback to get even better over time.

**Interactive CLI:**
The command-line interface uses the Rich library to make your experience as user-friendly and visually appealing as possible.
