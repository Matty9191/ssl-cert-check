from flask import Response, Flask, request
import prometheus_client
from prometheus_client.core import CollectorRegistry
from prometheus_client import Summary, Counter, Histogram, Gauge
import time
from jsonParser import *
from getExpiryDays import *
import sys, getopt


app = Flask(__name__)

_INF = float("inf")

registry = CollectorRegistry()
graphs = {}

# app config
appConfigPath = '/config.json'
appPort = '9100'
appHost = '0.0.0.0'

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
def requests_gauge():
    res = []
    for k,v in graphs.items():
        res.append(prometheus_client.generate_latest(v))
    return Response(res, mimetype="text/plain")

def usage():
    print('Usage: app.py -c <config-json> [optional]')
    print('    -c  : specify json config')
    print('    -p  : port (default: 9100')
    print('    -h  : host (default: 0.0.0.0)')

def main(argv):
    try:
        if len(sys.argv) <= 1:
            print("ERROR: no argument specfied")
            usage()
            sys.exit(1)
        opts, args = getopt.getopt(argv, "c:p:")
    except getopt.GetoptError as exc:
        print('Invalid option ' + exc.opt + ' : ' + exc.msg)
        usage()
        sys.exit(1)
    
    for opt, arg in opts:
        if opt == '-c':
            appConfigPath = arg
            print('INFO: Config : ->', appConfigPath)
        elif opt == '-p':
            appPort = arg
            print('INFO: Port : -> ', appPort)
        elif opt == '-h':
            appHost = arg
            print('INFO: Port : -> ', appHost)

if __name__ == "__main__":
    main(sys.argv[1:])
    app.run(host=appHost, port=appPort, debug=True)