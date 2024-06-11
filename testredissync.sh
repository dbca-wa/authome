#!/bin/bash

is_number='^[0-9]+$'
if [[ "$1" == "" ]] 
then
    rediscluster stop 6383
    dbsize=$(redis-cli -p 6380 dbsize)
    echo "Found ${dbsize} keys in cluster 6380,dbsize = ${dbsize}"
elif [[ $1 =~ ${is_number} ]] 
then
    rediscluster stop 6383
    redis-cli  -p 6380 flushdb
    i=0
    counter=0
    while [[ $counter -lt $1 ]]
    do
        key="testkey_${i}"
        value=${i}
        slotid=$(redis-cli -c -p 6380 cluster keyslot ${key})
        if [[ $slotid -lt 5461 ]]
        then
          redis-cli -c -p 6380 set ${key} ${value} >/dev/null 2>&1
          ((counter++))
          if [[ $((counter % 1000)) -eq 0 ]]
          then
              echo "${counter} keys are generated"
          fi
        fi
        ((i++))
    done
    dbsize=$1
    echo "${counter} keys are set in cluster 6380,dbsize = ${dbsize}"
else
    echo "Please specify the number of keys which need to be generated"
    exit 1
fi

master_res=$(redis-cli -c -p 6380 info replication)
slave0_res=$(echo -e "${master_res}" | grep "slave0")
IFS=',' read -ra ADDR <<< "${slave0_res}"
for i in "${ADDR[@]}"; do
  if [[ $i = offset=* ]]
  then
      slave0_offset=$i
  fi
done
rediscluster start 6383
slave_key_value=""
master_moffset=1
slave0_offset=2
slave_moffset=3
slave_soffset=4
while [[ ${master_moffset} -ne ${slave0_offset} ]] || [[ ${slave_moffset} -ne ${slave_soffset} ]]
do
    echo "********************************************************"
    slave_dbsize=$(redis-cli -p 6383 dbsize)
    slave_res=$(redis-cli -c -p 6383 info replication)
    master_res=$(redis-cli -c -p 6380 info replication)

    slave0_res=$(echo -e "${master_res}" | grep "slave0")
    if [[ "${slave0_res}" == "" ]]
    then
        slave0_offset=0
    else
        IFS=',' read -ra datas <<< "${slave0_res}"
        slave0_offset=""
        for i in "${datas[@]}"; do
            if [[ $i = offset=* ]]
            then
                slave0_offset=${i#offset=}
                slave0_offset=$(echo "${slave0_offset}" | tr -dc '0-9')
            fi
        done
    fi
    master_moffset=$(echo -e "${master_res}" | grep "master_repl_offset")
    master_moffset=$(echo "${master_moffset}" | tr -dc '0-9')

    slave_moffset=$(echo -e "${slave_res}" | grep "master_repl_offset")
    slave_moffset=$(echo "${slave_moffset}" | tr -dc '0-9')

    slave_soffset=$(echo -e "${slave_res}" | grep "slave_repl_offset")
    slave_soffset=$(echo "${slave_soffset}" | tr -dc '0-9')

    echo "master: master offset=${master_moffset} slave offset=${slave0_offset} dbsize=${dbsize}"
    echo "slave : master offset=${slave_moffset} slave offset=${slave_soffset} dbsize=${slave_dbsize}"
done
