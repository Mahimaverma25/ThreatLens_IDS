import requests

def send_alert(data):

    url = "http://localhost:5000/api/alerts"

    requests.post(url, json=data)