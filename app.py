from flask import Flask, render_template, request, jsonify
from detector import analyze

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze_email():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Missing 'email' field"}), 400
    email_text = data["email"].strip()
    if not email_text:
        return jsonify({"error": "Email text is empty"}), 400
    return jsonify(analyze(email_text))

if __name__ == "__main__":
    app.run(debug=True, port=5001)
