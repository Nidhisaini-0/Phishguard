# PhishGuard 🛡️

**A simple phishing link checker that tells you if a link is safe, suspicious, or dangerous, in plain language.**

PhishGuard checks a link and gives a traffic-light verdict with clear reasons, so anyone can understand the result without knowing anything about cybersecurity.

| Verdict | Meaning |
|---------|---------|
| 🟢 Green | Looks safe |
| 🟡 Yellow | Suspicious, be careful |
| 🔴 Red | Likely phishing, do not click |

## Why this project?

Phishing is one of the most common ways people get hacked, and most warnings are too technical for everyday users. PhishGuard explains *why* a link looks risky in simple words.

## Features

- Paste a link and get an instant green / yellow / red verdict
- Plain-language explanation for every result
- Firefox browser extension that checks links while you browse
- Lightweight Flask backend that does the analysis

## Project structure

```
Phishguard/
├── backend/      # Flask server with the link analysis logic
├── extension/    # Firefox browser extension
├── requirements.txt
└── README.md
```

## Getting started

### 1. Clone the repository

```bash
git clone https://github.com/Nidhisaini-0/Phishguard.git
cd Phishguard
```

### 2. Run the backend

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd backend
python app.py
```

The server runs locally (by default at `http://127.0.0.1:5000`). Change `app.py` to your actual main file name if it differs.

### 3. Load the Firefox extension

1. Open Firefox and go to `about:debugging`
2. Click **This Firefox**
3. Click **Load Temporary Add-on...**
4. Select the `manifest.json` file inside the `extension/` folder

Keep the Flask server running while you use the extension.

## How it works

1. You give PhishGuard a link (pasted, or from the extension).
2. The Flask backend analyses the link for common phishing warning signs.
3. It returns a verdict (green, yellow, or red) along with reasons in plain language.
4. The result is shown to you right away.

## Tech stack

- Python, Flask
- JavaScript, HTML, CSS (Firefox extension)

## Future improvements

- Check pasted emails, not just links
- Publish the extension to the Firefox Add-ons store
- Host the backend online
- Add more detection signals

## Built for

A hackathon project, built in 5 days.

## License

MIT
