from flask import Flask, request, render_template, render_template_string
import requests

app = Flask(__name__)

@app.route("/")
def index():
	return render_template('malsite_POST.html')

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8126)