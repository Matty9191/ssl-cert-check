import ssl
import OpenSSL
import datetime
from datetime import date
import jks

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1


def getRemoteExpiryDays(certInfo):
    cert = ssl.get_server_certificate((certInfo['path'],certInfo['port']))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    expiryTime = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
    currentTime = datetime.date.today().strftime('%s')
    daysRemain = int(expiryTime) - int(currentTime)

    return { certInfo['path']: int(daysRemain/(60*60*24)) } 

def getJKSExpiryDays(certInfo):

    keystore = jks.KeyStore.load(certInfo['path'], certInfo['passphrase'])
    jksDict = {}
    for alias, pk in keystore.private_keys.items():
        pk_entry = keystore.private_keys[alias]
        public_cert = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
        expiryTime = datetime.datetime.strptime(public_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
        currentTime = datetime.date.today().strftime('%s')
        daysRemain = int(expiryTime) - int(currentTime)
        jksDict[alias]=daysRemain/(60*60*24)
    return jksDict


def getPEMExpiryDays(certInfo):
    cert = open(certInfo['path'], 'rt').read()
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    expiryTime = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
    currentTime = datetime.date.today().strftime('%s')
    daysRemain = int(expiryTime) - int(currentTime)
    return { certInfo['path']: daysRemain/(60*60*24) } 

#print(getRemoteExpiryDays({ 'path': "google.com", 'port': '443'}))
#print(getPEMExpiryDays({ 'path':"certs/test.pem"}))
#print(getJKSExpiryDays({ 'path': "certs/test.jks", 'passphrase': 'changeit' } ))
