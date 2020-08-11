#!/bin/sh
#
# Test fpos_t type shell script for BUGS
# 
# V 0.1, 26 July 2002 
# Sylvain Martinez.
#
# -> 26 July 2002 - V0.1 - First draft of the script to test what fpos_t type
#                          we are using
#

cd apps/
make testfpost 2>/dev/null
if [ $? -eq 0 ]; then
echo "Using new fpos_t type" 
echo "Creating fpos_t.h file"
echo "#define _NEWFPOS_T 1" > ../include/fpos_t.h
else
echo "#define _NEWFPOS_T 0" > ../include/fpos_t.h
fi
