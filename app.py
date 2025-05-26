from flask import Flask, render_template, request, jsonify
from detector import PhishingDetector

app = Flask(__name__)
detector = PhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/email', methods=['GET', 'POST'])
def email_analysis():
    if request.method == 'POST':
        email_content = request.form.get('email_content', '')
        sender = request.form.get('sender', '')
        result = detector.analyze_email(email_content, sender)
        return render_template('email.html', result=result, email_content=email_content, sender=sender)
    return render_template('email.html')

@app.route('/website', methods=['GET', 'POST'])
def website_analysis():
    if request.method == 'POST':
        url = request.form.get('url', '')
        result = detector.analyze_website(url)
        return render_template('website.html', result=result, url=url)
    return render_template('website.html')

@app.route('/api/email', methods=['POST'])
def api_email_analysis():
    data = request.get_json()
    email_content = data.get('email_content', '')
    sender = data.get('sender', '')
    result = detector.analyze_email(email_content, sender)
    return jsonify(result)

@app.route('/api/website', methods=['POST'])
def api_website_analysis():
    data = request.get_json()
    url = data.get('url', '')
    result = detector.analyze_website(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)