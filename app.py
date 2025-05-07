from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"message": "Welcome to Fetchbot API test"})

@app.route('/api/v1/status')
def status():
    return jsonify({"status": "operational"})

if __name__ == '__main__':
    app.run(debug=True)