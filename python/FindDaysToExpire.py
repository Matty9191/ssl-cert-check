import ssl
import OpenSSL
import datetime
from datetime import date
import jks
from OpenSSL import crypto

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1


def get_remote_expiry_days(cert_info):
    cert_expire_data = {}
    cert = ssl.get_server_certificate((cert_info['path'],cert_info['port']))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    time_to_expire = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
    current_time = datetime.date.today().strftime('%s')
    days_left = int(time_to_expire) - int(current_time)

    cert_expire_data[cert_info['path']]=int(days_left/(60*60*24))
    return cert_expire_data 

def get_jks_days_to_expire(cert_info):

    keystore = jks.KeyStore.load(cert_info['path'], cert_info['passphrase'])
    cert_expire_data = {}
    for alias, pk in keystore.private_keys.items():
        pk_entry = keystore.private_keys[alias]
        public_cert = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
        time_to_expire = datetime.datetime.strptime(public_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
        current_time = datetime.date.today().strftime('%s')
        days_left = int(time_to_expire) - int(current_time)
        cert_expire_data[alias]=int(days_left/(60*60*24))
    return cert_expire_data


def get_pem_days_to_expire(cert_info):

    cert_expire_data = {}
    cert = open(cert_info['path'], 'rt').read()
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    time_to_expire = datetime.datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
    current_time = datetime.date.today().strftime('%s')
    days_left = int(time_to_expire) - int(current_time)
    cert_expire_data[cert_info['path']]=int(days_left/(60*60*24))
    return cert_expire_data 

def get_pkcs_days_to_expire(cert_info):

    cert_expire_data = {}
    x509 = crypto.load_pkcs12(open(cert_info['path'], 'rb').read(), bytes(cert_info['passphrase'], 'utf-8') )
    time_to_expire = datetime.datetime.strptime(x509.get_certificate().get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%s')
    current_time = datetime.date.today().strftime('%s')
    days_left = int(time_to_expire) - int(current_time)
    cert_expire_data[cert_info['path']]=int(days_left/(60*60*24))
    return cert_expire_data 

