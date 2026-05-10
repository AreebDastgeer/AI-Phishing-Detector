from flask import Flask, render_template, request
import joblib
from urllib.parse import urlparse
from feature_extraction import extract_features

app = Flask(__name__)

model = joblib.load("phishing_model_RF.pkl")

@app.route("/", methods=["GET", "POST"])
def home():

    prediction = None
    confidence = None
    url = ""

    if request.method == "POST":

        url = request.form["url"]

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        features = extract_features(url)
        features = [features]  
        trusted_domains = [
            "google.com",
            "facebook.com",
            "paypal.com",
            "amazon.com",
            "youtube.com"
        ]

        domain = urlparse(url).netloc.replace("www.", "")

        if domain in trusted_domains:
            prediction = "✅ Safe Website"
            confidence = 0

        else:
            result = model.predict(features)[0]


            probs = model.predict_proba(features)[0]

            # FIX: ensure correct class mapping
            classes = model.classes_
            phishing_index = list(classes).index(1)

            confidence = round(probs[phishing_index] * 100, 2)
            


            if result == 1:
                prediction = "⚠️ Phishing Website Detected"
            else:
                prediction = "✅ Safe Website"

    return render_template(
        "index.html",
        prediction=prediction,
        confidence=confidence,
        url=url
    )

if __name__ == "__main__":
    app.run(debug=True)