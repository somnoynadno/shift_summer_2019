#!/usr/bin/python3.6
from flask import Flask, request, render_template, render_template_string
import requests

app = Flask(__name__)

def lfi_search(ip,port,param):
	file = open('lfi.txt','r')
	res = []
	for x in file:
		payload = str('http://'+ip+':'+port+'?'+param+'='+x).strip('\n')
		r = requests.get(payload)
		res.append(r.text)
	return(res)

@app.route("/")
def index():
	return render_template_string('Hello World!')


@app.route("/gun", methods=['GET', 'POST'])
def lfi():
	if request.method == 'POST':
		ip = str(request.form['ip'])
		port = str(request.form['port'])
		param = str(request.form['param'])
		result = lfi_search(ip,port,param)
		return render_template('gun.html', ip=ip,port=port, param=param,result=result)
	else:
		return render_template('gun.html')

@app.route("/hehehe")
def hehehe():
	return render_template_string('lalka')

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8123,debug=True)
