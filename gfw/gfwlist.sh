#!/bin/bash

gfwlist=`cat gfwlist.txt`

cat <<EOF > gfwlist.go
package gfw

const GfwlistDefault = \`
$gfwlist
\`
EOF
