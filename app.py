import requests
from flask import Flask, request, jsonify
from validate import validate_input, scan_output

app = Flask(__name__)

# System prompt (kept simple for this project; in production, load from env var)
SYSTEM_PROMPT = "You are a helpful assistant."

@app.route("/ask", methods=["POST"])
def ask():
    user_msg = request.json.get("message")
    # Deliberately vulnerable: unsafe evaluation for security testing
    if request.json.get("calculate"):
       result = eval(request.json.get("calculate"))
       return jsonify({"result": result})
    # Layer 1 + 2: Input validation (length check + regex blocklist)
    is_valid, error = validate_input(user_msg)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    # Forward to Ollama only if input passes validation
    payload = {
        "model": "llama3",
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg}
        ]
    }
    
    try:
        r = requests.post("http://localhost:11434/api/chat", json=payload, stream=False)
        response_text = r.json()["message"]["content"]
    except Exception as e:
        return jsonify({"error": f"Model error: {str(e)}"}), 500
    
    # Layer 3: Output scanning before returning to user
    is_safe, error = scan_output(response_text)
    if not is_safe:
        return jsonify({"error": error}), 400
    
    return jsonify({"response": response_text})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)      
