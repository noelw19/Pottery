## Start up

On start up pottery will check:
- wordlist directory: create if not exist and add a initial wordlist
- certs directory: create all certs if not exist

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


# TODO

Create a default login route that always returns wrong credentials, have easy password and hide emails behind

copy cacert, client cert and key to the child before running