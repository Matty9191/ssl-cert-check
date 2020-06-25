from flask import Response, Flask, request
import prometheus_client
from prometheus_client.core import CollectorRegistry
from prometheus_client import Summary, Counter, Histogram, Gauge
import time
from jsonParser import *
from getExpiryDays import *

app = Flask(__name__)

_INF = float("inf")

registry = CollectorRegistry()
graphs = {}

graphs['c'] = prometheus_client.Gauge(
    "certs_expiry_dates",
    "certs expiry dates",
    ["certName", "certAlias","certPath"],
    registry=registry,
)


@app.route("/")
def main():
    daysDict = {}
    certsArray = jsonParser('config.json')
    for info in certsArray:
        if (info['type'] == 'JKS'):
            daysDict = getJKSExpiryDays(info)
        elif(info['type'] == 'PEM'):
            daysDict = getPEMExpiryDays(info)
        elif(info['type'] == 'PKCS'):
            daysDict = getPKCSExpiryDays(info)
        elif(info['type'] == 'URL'):
            daysDict = getRemoteExpiryDays(info)
        else: 
            print('Format not supported')  
        for alias in daysDict:
            graphs['c'].labels(info['name'], alias, info['path']).set(daysDict[alias])
    return 'Check the /metrics for more details'

@app.route("/metrics")
def requests_count():
    res = []
    for k,v in graphs.items():
        res.append(prometheus_client.generate_latest(v))
    return Response(res, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=True)