import requests

for x in range(1,65536):
	r = requests.get('http://127.0.0.1/get_url_requests?url=http://127.0.0.1:'+str(x)+'/')
	if r.status_code != 200:
		print("port", x, "closed");
	else:
		print("port", x, "open");