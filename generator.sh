#!/bin/bash

input="./input/list.html"
wget -O ${input} "https://s3.amazonaws.com/download.draios.com/stable/sysdig-probe-binaries/index.html"

for i in {10..17}
do
    cat header.template > ${i}.html
    cat ${input} | grep "falco-probe-0.${i}.0" | grep href | cut -f2 -d"\"" | awk -F"-" '{print "<tr><th>"$3"</th><th>"$4"</th><th>"$5"-"$6"</th><th><a href=\"./"$0"\" download=\""$0"\"><span class=\"glyphicon glyphicon-download-alt\"></span></a></th></tr>"}' >> ${i}.html
    cat footer.template >> ${i}.html
done
