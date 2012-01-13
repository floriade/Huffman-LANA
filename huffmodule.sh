#!/bin/sh
# My module initialization

if [ $1 = "up" ] 
	then
	echo LANA initialization running...
	cd /home/floriade/lanareloaded/lana/src
	insmod lana.ko
	insmod fb_eth.ko
	insmod fb_huff.ko
	cd ../usr/
	./vlink ethernet hook eth0
	./fbctl add fb2 huff
	./fbctl bind fb2 eth0
	echo ...done
elif [ $1 = "down" ] 
	then
	echo LANA deinitialization running...
	cd /home/floriade/lanareloaded/lana/usr/
	./fbctl unbind fb2 eth0
	sleep 0.25
	./vlink ethernet unhook eth0
	sleep 0.25
	./fbctl rm fb2
	sleep 0.25
	rmmod fb_eth.ko
	sleep 0.25
	rmmod fb_huff.ko
	sleep 0.25
	rmmod lana.ko
	echo ...done
else
	echo Valid parameter are either up or down
fi
