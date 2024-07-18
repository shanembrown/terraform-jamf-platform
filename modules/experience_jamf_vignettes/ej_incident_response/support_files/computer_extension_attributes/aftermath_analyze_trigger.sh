#!/bin/bash

if [ -e /Library/.tje/analyze ]; then
	echo "<result>analyze</result>"
else
	echo "<result></result>"
fi

exit 0