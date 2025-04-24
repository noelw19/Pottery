#!/bin/bash

go build main.go
rm -rf ../test/main
cp ./main ../test/