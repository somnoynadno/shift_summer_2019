from flask import Flask, request, render_template
import pycurl
import re
import socket
import requests
from io import BytesIO

app = Flask(__name__)

blacklist = ['127.']
allowed_schemes = ['http','https']

def check_url_schemes(url):
	for schema in allowed_schemes:
		result = re.match(schema+'://', url)
		if result: return 0
	return 1

def check_dns(url):
	dns=url.split('//')[1].split('/')[0]
	ip_list = []
	ais = socket.getaddrinfo(dns,0,0,0,0)
	for result in ais:
		for addr in blacklist:
			check = re.match(addr, result[-1][0])
			if check: return 1
		ip_list.append(result[-1][0])
	ip_list = list(set(ip_list))
	return 0

@app.route("/")
def hello():

	ip = request.remote_addr

	return render_template('index.html', ip=ip)


@app.route("/get_url_curl")
def get_url_curl():

	url = request.args.get('url')

	if url is None:
		url = 'https://ya.ru'

	if check_url_schemes(url) or check_dns(url):
		return render_template('access_deny.html')

	# prepare curl
	curl_wrap = pycurl.Curl()

	# prepare buffer for curl output
	buffer = BytesIO()

	# settings for curl: url and output
	curl_wrap.setopt(curl_wrap.URL, url)
	curl_wrap.setopt(curl_wrap.WRITEDATA, buffer)

	# let's go!
	curl_wrap.perform()

	# get output
	info = buffer.getvalue()
	info = info.decode()

	return render_template('result.html', info=info)


@app.route("/get_url_requests")
def get_url_requests():

	url = request.args.get('url')

	if url is None:
		url = 'https://ya.ru'

	if check_url_schemes(url) or check_dns(url):
		return render_template('access_deny.html')

	info = requests.get(url).text

	return render_template('result.html', info=info)


@app.route("/secret")
def secret():

	ip = request.remote_addr

	if ip == '127.0.0.1':

		is_secret_view = False

		if request.args.get('show_me_secrets') == 'true':
			is_secret_view = True

		return render_template('secret.html', ip=ip, is_secret_view=is_secret_view)

	else:
		return 'Forbidden', 403


if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=80)
