import OpenSSL
import jks
import datetime
from datetime import date

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1

def jksfile2context(jks_file, passphrase, key_alias, key_password=None):
    keystore = jks.KeyStore.load(jks_file, passphrase)

    for alias, pk in keystore.private_keys.items():
        print("Alias: %s" % pk.alias)
        pk_entry = keystore.private_keys[alias]
        public_cert = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
        print(datetime.datetime.strptime(public_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))

jksfile2context('certs/test.jks', 'changeit', 'mock-1', key_password='changeit')

