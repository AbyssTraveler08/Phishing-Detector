<div align="center">

# 🎣 Phishing Link Detector

**A Flask-based web demo that evaluates URL characteristics using transparent, rule-based heuristics.**

<img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
<img src="https://img.shields.io/badge/Backend-Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
<img src="https://img.shields.io/badge/Security-URL%20Triage-0A66C2?style=for-the-badge" alt="URL triage" />

</div>

---

## 🔎 Overview

Phishing Link Detector is an educational web application with a small HTML interface and a Python/Flask backend. It extracts basic characteristics from a submitted URL and uses simple rules to flag suspicious-looking URLs.

The project demonstrates web request handling, URL parsing, feature extraction, JSON responses, and baseline phishing heuristics. It does not query a threat-intelligence feed or determine a site's reputation.

## ✨ Features

- Web form served from the local Flask application.
- URL feature extraction, including length, HTTPS usage, IP-like hostnames, at-signs, dot count, and selected suspicious words.
- Rule-based phishing indicator evaluation.
- JSON endpoint at **POST /check**.
- Basic per-client request-rate tracking in memory.
- Simple code organization separating URL analysis from the web entry point.

## 🧰 Requirements

- Python 3.
- Dependencies listed in **requirements.txt** (Flask and tldextract).

## ⚙️ Installation

~~~bash
git clone https://github.com/AbyssTraveler08/Phishing-Detector.git
cd Phishing-Detector

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
~~~

## 🚀 Run locally

~~~bash
python3 app.py
~~~

Open **http://127.0.0.1:5000/** in your browser. Start the server from the repository root so the application can load **index.html**.

The backend endpoint accepts JSON:

~~~bash
curl -X POST http://127.0.0.1:5000/check -H "Content-Type: application/json" -d '{"url":"https://example.com"}'
~~~

The response includes the submitted URL, the heuristic verdict, extracted features, the client address observed by the server, and a basic suspicious-request-rate flag.

## 🧠 How the heuristic works

The application checks URL traits such as:
- Whether the hostname resembles an IPv4 address.
- Whether the scheme is HTTPS.
- Whether the URL contains an at-sign.
- Whether the URL is unusually long.
- Whether the hostname has many dots.
- In the standalone feature module, selected words and hyphen use are also considered.

These features are weak signals in isolation: legitimate sites may trigger a rule, while sophisticated phishing sites can avoid the patterns.

## 🧪 Testing suggestions

- Submit a reserved test URL such as https://example.com.
- Try a deliberately malformed URL as a validation case.
- Check the JSON response from POST /check.
- Test requests with missing JSON or a missing URL field.
- Review both false positives and false negatives before adjusting the rules.

Do not test with real credentials or send sensitive URL data to third-party services.

## ⚠️ Security, privacy, and limitations

- The verdict is a heuristic result, not a guarantee of safety or maliciousness.
- The current app uses Flask's development server with debug mode enabled. Keep it bound to localhost during development; do not expose this configuration to the public internet.
- Rate tracking is stored in process memory and is not a production abuse-prevention mechanism.
- HTTPS alone does not prove a website is legitimate.
- Do not open suspected phishing URLs on your primary workstation just to test them.

## 🗺️ Roadmap

- Add unit tests for feature extraction and classification thresholds.
- Normalize and validate URLs more thoroughly.
- Make scoring rules explicit and configurable.
- Improve error handling and production-safe server configuration.
- Add optional reputation checks behind explicit analyst control.

## 👤 Author

**Amar Kant Yadav** · [GitHub profile](https://github.com/AbyssTraveler08)

## 📄 License

See the repository's LICENSE file.

---

<div align="center">Built for phishing-awareness learning and defensive URL triage.</div>
