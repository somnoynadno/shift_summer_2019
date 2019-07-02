import requests

for x in range(1,65536):
	# r = requests.get('http://127.0.0.1/get_url_curl?url=127.0.0.1:'+str(x))
	r = requests.get('http://127.0.0.1/get_url_requests?url=127.0.0.1:'+str(x))
	if r.text != '':print("port", x, "closed");