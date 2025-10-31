from flask import Flask, jsonify, request


app = Flask(__name__)

@app.route('/', methods = ['POST'])
def post():
    if request.headers['Content-Type'] != 'applications/octet-steam':
        return jsonify({'error': 'expecting binary data'}), 400
    
    bytez = request.data
    # import a model and have a predict function then return it
