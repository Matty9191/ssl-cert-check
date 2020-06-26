from flask import Response, Flask, request
import prometheus_client
from prometheus_client.core import CollectorRegistry
from prometheus_client import Summary, Counter, Histogram, Gauge
import time
from JsonParser import *
from FindDaysToExpire import *
import sys, getopt


app = Flask(__name__)

_INF = float("inf")

registry = CollectorRegistry()
graphs = {}

# app config
app_config_path = '/config.json'
app_port = '9100'
app_host = '0.0.0.0'

graphs['c'] = prometheus_client.Gauge(
    "certs_expiry_dates",
    "certs expiry dates",
    ["certName", "certAlias","certPath"],
    registry=registry,
)

@app.route("/")
def main():
    certs_data = {}
    certs_arr = json_parser(app_config_path)
    for info in certs_arr:
        if (info['type'] == 'JKS'):
            certs_data = get_jks_days_to_expire(info)
        elif(info['type'] == 'PEM'):
            certs_data = get_pem_days_to_expire(info)
        elif(info['type'] == 'PKCS'):
            certs_data = get_pkcs_days_to_expire(info)
        elif(info['type'] == 'URL'):
            certs_data = get_remote_expiry_days(info)
        else: 
            print('Format not supported')  
        for alias in certs_data:
            graphs['c'].labels(info['name'], alias, info['path']).set(certs_data[alias])
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
            app_config_path = arg
            print('INFO: Config : ->', app_config_path)
        elif opt == '-p':
            app_port = arg
            print('INFO: Port : -> ', app_port)
        elif opt == '-h':
            app_host = arg
            print('INFO: Port : -> ', app_host)

if __name__ == "__main__":
    main(sys.argv[1:])
    app.run(host=app_host, port=app_port, debug=True)