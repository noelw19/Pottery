#!/bin/bash

echo "Running cert copier"

rm -rf ./certs/ca/*
rm -rf ./certs/client/*
cd ../test/certs
cp -r ./ca ../../honeypot/certs/
cp -r ./client ../../honeypot/certs/

echo "Finished cert copier"

