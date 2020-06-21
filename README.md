# cert-expiry-checker

# Generate sample certs file

```
export certName=https-1
export time=15
keytool -genkey -alias ${certName} -storetype pkcs12 -keystore ${certName}.pkcs12 -keyalg RSA -keysize 2048 -validity ${time}

export certName=https-2
export time=30
keytool -genkey -alias ${certName} -storetype pkcs12 -keystore ${certName}.pkcs12 -keyalg RSA -keysize 2048 -validity ${time}

export certName=https-3
export time=45
keytool -genkey -alias ${certName} -storetype pkcs12 -keystore ${certName}.pkcs12 -keyalg RSA -keysize 2048 -validity ${time}
```

# config file
certs.json

```
{
    "certs":
    [
        {
            "name":"cert 1",
            "pass":"changeit",
            "path":"/certs/https-1.pkcs12",
            "type":"PKCS12"
        },
        {
            "name":"cert 2",
            "pass":"changeit",
            "path":"/certs/https-2.pkcs12",
            "type":"PKCS12"
        },
        {
            "name":"cert 3",
            "pass":"changeit",
            "path":"/certs/https-3.pkcs12",
            "type":"PKCS12"
        }
    ]
}
```

### Note: Make sure you encrypt this config file.

# How to override default config.json path

```
cert-expiry-checker --config /certs.json
```

# Sample logs

```
ERROR: 101 | cert 1 | /certs/https-1.pkcs12 | This cert will expire in 14 days. !!! Renew ASAP !!!
WARN: 101 | cert 2 | /certs/https-2.pkcs12 | This cert will expire in 29 days. !!! Renew Soon !!!
INFO: 101 | cert 3 | /certs/https-3.pkcs12 | This cert will expire in 44 days. !!! All Good !!!
ERROR: 103 | cert 4 | /crts/https-3.pkcs12 | Not able to get certs information
ERROR: 103 | cert 5 | /crts/https-3.pkcs12 | Not able to get certs information
ERROR: 103 | cert 6 | /crts/https-3.pkcs12 | Not able to get certs information
```
