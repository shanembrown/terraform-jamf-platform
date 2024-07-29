#!/bin/sh

if [ -e /Library/.tje/aftermath ]; then
	echo "<result>aftermath</result>"
else
	echo "<result></result>"
fi

exit 0