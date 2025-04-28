## About

Pottery allows multiple honey pots to be dynamically set up on multiple ports

Features:
- dynamic endpoints that are generated using common fuzzing wordlists, wordlists can be added by users.
- ability to set an instance as a parent and receive MTLS requests from child instances to store data for redundancy.
- config file to give an instance a naming scheme for easier reading of data.
- collects IP data, geolocation data of IP, request data such as request headers, body, endpoint
- uses sqlite as DB
- includes rate limiting and IP blacklisting
- generates its own certificate authory certificates and server + client certificates to provide MTLS communication between parent and child.
- [In progress] adding functionality to detect possible fuzzing by searching endpoint against common endpoints malicious actors may look for such as .git, db.ini etc and executing a fuzzing alert.

## Start up

On start up pottery will check:
- wordlist directory: create if not exist and add a initial wordlist
- certs directory: create all certs if not exist
- config will be check if not exists will create config file and save defaults

#### Renew all certificates
delete certs directory and rerun application - will only work if is parent or by using the -generateCerts flag in the cli

eg: ./pottery -generateCerts

#### if instance has a parent:  
it will check that cacert, client.crt and client.key exist and test connection before starting honeypots

#### if is a parent:
Will check that all certs exist within certs
- certs
    - ca
        - ca.crt
        - ca.key
    - server
        - server.crt
        - server.key
    - client
        - client.crt
        - client.key


## config

config file should be set in the same dir as the exe
named config.json

#### ports

eg:
`"ports": [8080, 8081]`

if no ports are supplied this defaults to a single port of 8080

#### endpoint count

this config sets the amount of endpoints per pot

#### Parent

if the parent is set to `none` then it will not set up an mtls server or client

if set to loopback address `127.0.0.1:8080` it is considered parent and will set up a mtls server to receive requests to store data

else it has a parent and will set up a mtls client to send requests for storage purposes.

#### NamingScheme

Just a naming scheme for pots fired, will append a number to each pot fired
i.e vallhala-0

# TODO
