#!/bin/bash

if [ -z "$CFLAGS" ]
then
  CFLAGS='-DFRAME_802154_CONF_SECURITY=1'
#  CFLAGS='-DFRAME_802154_CONF_SECURITY=1 -DTEST_FRAME_802154_SECURITY'
fi

CFLAGS1="$CFLAGS"

#rm -f obj_minimal-net-2/node-id.*
#make clean
rm -fr obj_minimal-net-2 obj_n1122
rm -f contiki-minimal-net-2.a
export CFLAGS="$CFLAGS1 -DMY_NODE_ID=0x1122"
make -j6 && cp -f ./example-ping6.minimal-net-2 ./example-ping6.n1122
mv obj_minimal-net-2 obj_n1122

#rm -f obj_minimal-net-2/node-id.*
#make clean
rm -fr obj_minimal-net-2 obj_n1133
rm -f contiki-minimal-net-2.a
export CFLAGS="$CFLAGS1 -DMY_NODE_ID=0x1133"
make -j6 && cp -f ./example-ping6.minimal-net-2 ./example-ping6.n1133
mv obj_minimal-net-2 obj_n1133

# run make twice...
# make clean; CFLAGS='-DMY_NODE_ID=0x1133 -DFRAME_802154_CONF_SECURITY=1 -DTEST_FRAME_802154_SECURITY' make -j8

