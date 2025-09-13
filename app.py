from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains on all routes

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'ok',
    })

if __name__ == '__main__':
    app.run(
        debug=True,
        host='0.0.0.0',
        port=5000,
        use_reloader=True,  # Enable auto-reload on file changes
        use_debugger=True   # Enable interactive debugger
    )
