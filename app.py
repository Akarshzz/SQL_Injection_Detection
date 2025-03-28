from flask import Flask, request, jsonify
import joblib

# Load the trained model
model = joblib.load("sqli_rf_model.pkl")

app = Flask(__name__)


# Inline HTML + CSS for simplicity
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SQLi Detection</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { text-align: center; }
        form { display: flex; flex-direction: column; max-width: 500px; margin: 0 auto; }
        label, select, input, button { margin-bottom: 15px; padding: 10px; font-size: 16px; }
        button { background: #28a745; color: white; border: none; cursor: pointer; }
        button:hover { background: #218838; }
        .result { text-align: center; font-size: 18px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>SQL Injection Detection</h1>
    <form method="POST" action="/">
        <label for="method">HTTP Method:</label>
        <select id="method" name="method" required>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
        </select>

        <label for="query">Enter SQL Query:</label>
        <input type="text" id="query" name="query" placeholder="Enter SQL query" required>

        <button type="submit">Detect</button>
    </form>

    {% if result %}
    <div class="result" style="color: {% if is_attack %}red{% else %}green{% endif %};">
        {{ result }}
    </div>
    {% endif %}
</body>
</html>
"""

# Route for both front-end display and detection
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        query = request.form.get('query')
        method = request.form.get('method')

        # Feature extraction
        query_length = len(query)
        special_chars = sum(1 for char in query if char in ";'=-")
        sql_keywords = ["SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "UNION", "OR", "AND"]
        keyword_count = sum(1 for keyword in sql_keywords if keyword.lower() in query.lower())
        method_encoded = 1 if method == "POST" else 0

        # Prepare features
        features = [[1, query_length, special_chars, keyword_count, method_encoded, 0]]

        # Predict using the model
        prediction = model.predict(features)[0]

        # Display result
        result = "SQL Injection Detected!" if prediction == 1 else "Normal Request"
        is_attack = prediction == 1

        # Render the same page with result
        return HTML_PAGE.replace("{% if result %}", "").replace("{{ result }}", result).replace("{{ is_attack }}", str(is_attack).lower())

    return HTML_PAGE.replace("{% if result %}", "")

if __name__ == '__main__':
    app.run(debug=True)
