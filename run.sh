#!/usr/bin/env bash

set -e

interfaceName=$(ip -o a | grep -o "[0-9]\+: [ew].\+" | awk '{print $2}' | head -n 1)

mkdir -p ./output
outputPcap='./output/catch.pcap' 

echo "find interface ${interfaceName}"
echo "save file ${outputPcap}"

if [ ! -z "$1" ]; then
    echo "start -e ${interfaceName} -w ${outputPcap} -b ${bpfExpr}"
    sudo bin/app -e ${interfaceName} -w ${outputPcap} -b ${bpfExpr}
else
    echo "start -e ${interfaceName} -w ${outputPcap}"
    sudo bin/app -e ${interfaceName} -w ${outputPcap}
fi



