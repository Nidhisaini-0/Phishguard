from flask import Flask, request, jsonify, send_from_directory
from scorer import analyze_url

app = Flask(__name__, static_folder="static")


@app.after_request
def add_cors(resp):
    # Lets a browser extension (stretch goal) call the API
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/")
def home():
    return send_from_directory("static", "index.html")


@app.route("/api/check", methods=["POST", "OPTIONS"])
def check():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL"}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL is too long"}), 400
    return jsonify(analyze_url(url))


if __name__ == "__main__":
    app.run(debug=True)