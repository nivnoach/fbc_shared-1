#!/bin/sh
export ETH0_MAC_ADDR=`ifconfig | grep eth0 | awk '{print $5}'`
/usr/bin/envsubst < /app/radius_proxy.config.template > /app/radius_proxy.conf
/app/radius_proxy -c /app/radius_proxy.conf -d | tee /proc/1/fd/1 | /scribedog/scribedog -config /scribedog/scribedog.ini -file=-
