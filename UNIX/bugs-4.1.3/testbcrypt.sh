#!/bin/sh
#
# Test shell script for BUGS
# V 0.5, 15 November 2000
# Sylvain Martinez.
#
# -> 15 November 2000 - V0.5 - Changed the success message
#
# -> 14 November 2000 - V0.4 - Problem when the script was failing,
#                              it was trying to rediret the output into a file
#

./bin/bcrypt -u -s cryptedtext -d uncryptedtext -pwd helloworld -quiet

TESTING=`/bin/cat ./uncryptedtext`

/bin/rm -f ./uncryptedtext

if [ "If you can see this BUGS is working !" = "$TESTING" ]; then 
 echo
 echo "--->"
 echo "---> TEST SUCCESSFULL."
 echo "---> bcrypt and the BUGS cryptography library are working Correctely."
 echo "--->"
 echo
 exit 0
fi

echo
echo "--->"      
echo "---> TEST FAILED."
echo "---> Something went wrong..."
echo "---> Check if you have /bin/sh as you need it to run this test. You may as well want to replace /bin/sh by /bin/ksh"
echo "--->"
echo 
exit 1
