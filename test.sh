#!/bin/bash
set -e

#########Running Test#########
echo "Running Test"
pkgs="\
    github.com/codingeasygo/tun2conn/gfw\
    github.com/codingeasygo/tun2conn/log\
    github.com/codingeasygo/tun2conn/udpgw\
"

echo "mode: set" > a.out
for p in $pkgs;
do
 go test -v --coverprofile=c.out $p
 cat c.out | grep -v "mode" >>a.out
done

sudo go test -v --coverprofile=c.out github.com/codingeasygo/tun2conn
cat c.out | grep -v "mode" >>a.out
gocov convert a.out > coverage.json

##############################
#####Create Coverage Report###
echo "Create Coverage Report"
# cat coverage.json | gocov-xml -b $GOPATH/src > coverage.xml
cat coverage.json | gocov-html coverage.json > coverage.html

######
