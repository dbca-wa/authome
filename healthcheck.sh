#!/bin/bash
pingTimeout=1
monitorInterval=60
maxMonitorServers=3
AUTH2_MONITORING_DIR=~/projects/authome/monitoring
AUTH2_CLUSTERID=auth2-01
PORT=8070

nowseconds=$(date '+%s')
now=$(date '+%Y-%m-%d %H:%M:%S')
today=$(date '+%Y-%m-%d')
if [[ "${AUTH2_CLUSTERID}" == "" ]]; then
    mkdir -p "${AUTH2_MONITORING_DIR}/auth2/${HOSTNAME}"
    serverinfofile="${AUTH2_MONITORING_DIR}/auth2/serverinfo.html"
    monitoringfile="${AUTH2_MONITORING_DIR}/auth2/${HOSTNAME}/$(date '+%Y-%m-%d').html"
else
    mkdir -p "${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${HOSTNAME}"
    serverinfofile="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/serverinfo.html"
    monitoringfile="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${HOSTNAME}/${today}.html"
fi
if [[ ! -f "${serverinfofile}" ]]; then
    cp ~/projects/auth2_chart/static/auth2serverinfo.html "${serverinfofile}"
    if [[ "${AUTH2_CLUSTERID}" == "" ]]; then
        sed -i "0,/<title[^<]*<\/title>/s//<title>Auth2 Server Monitoring Data<\/title>/" ${serverinfofile}
        sed -i "0,/<span id=\"clusterhead\">[^<]*<\/span>s//<span id=\"clusterhead\">Auth2 Server Monitoring data<\/span>/" ${serverinfofile}
    else
        sed -i "0,/<title[^<]*<\/title>/s//<title>The auth2 cluster '${AUTH2_CLUSTERID}' Monitoring Data<\/title>/" ${serverinfofile}
        sed -i "0,/<span id=\"clusterhead\">[^<]*<\/span>/s//<span id=\"clusterhead\">Auth2 Cluster(${AUTH2_CLUSTERID}) Monitoring Data<\/span>/" ${serverinfofile}
    fi
fi

#check whether hostname exists or not
count=$(grep "<tr><td>${HOSTNAME}</td>" ${serverinfofile} | wc -l)
if [[ $count -eq 0 ]]; then
    #Add that auth2 server into serverinfo file
    sed -i "0,/<tbody>/s//<tbody>\n<tr><td>${HOSTNAME}<\/td><td id='${HOSTNAME}readytime'><\!--readytime--><\/td><td id='${HOSTNAME}heartbeat'>${now}<\!--heartbeat--><\/td><td id='${HOSTNAME}processingtime'><\!--processingtime--><\/td><td id='${HOSTNAME}status'><\!--status--><\/td><td><div id='${HOSTNAME}resusage'><\/div><\!--resusage--><\/td><td><ol id='${HOSTNAME}monitoring'><\/ol><\!--monitoring--><\/td><\/tr>/" ${serverinfofile}
    #Manage the number of servers in the serverinfo file
    count=$(grep "<tr.*</tr>" ${serverinfofile} | wc -l)
    if [[ $count -gt ${maxMonitorServers} ]]; then
        #delete outdated servers
        rows=$(($count - ${maxMonitorServers}))
        lastrow=$(awk '/<\/tbody>/{ print NR; exit }' ${serverinfofile})
        firstrow=$((${lastrow} - ${rows}))
        lastrow=$((${lastrow} - 1))
        sed -i -e "${firstrow},${lastrow}d" ${serverinfofile}
    fi
else
    sed -i "0,/<td id='${HOSTNAME}heartbeat'>.*<\!--heartbeat-->/s//<td id='${HOSTNAME}heartbeat'>${now}<\!--heartbeat-->/" ${serverinfofile}
fi

if [[ ! -f "${monitoringfile}" ]]; then
    cp ~/projects/auth2_chart/static/auth2monitoring.html "${monitoringfile}"
    if [[ "${AUTH2_CLUSTERID}" == "" ]]; then
        sed -i "0,/<title[^<]*<\/title>/s//<title>The monitoring data for auth2 server($HOSTNAME)<\/title>/" ${monitoringfile}
    else
        sed -i "0,/<title[^<]*<\/title>/s//<title>The monitoring data for auth2 server(${AUTH2_CLUSTERID}:$HOSTNAME)<\/title>/" ${monitoringfile}
    fi
    sed -i "0,/<ol id='${HOSTNAME}monitoring'>/s//<ol id='${HOSTNAME}monitoring'><li><a href='\/admin\/monitor\/${today}.html'>${today}<\/a><\/li>/" ${serverinfofile}
fi

starttime=$(date '+%s.%N')
wget --tries=1 --timeout=${pingTimeout} http://127.0.0.1:${PORT}/ping -o /dev/null -O /tmp/auth2_ping.json
status=$?
echo "status=${status}"
endtime=$(date '+%s.%N')
pingtime=$(perl -e "print (${endtime} - ${starttime}) * 1000")

sed -i "0,/<td id='${HOSTNAME}processingtime'>.*<\!--processingtime-->/s//<td id='${HOSTNAME}processingtime'>$(printf %.2f ${pingtime}) ms<\!--processingtime-->/" ${serverinfofile}
#set auth2 starttime
if [[ $status -eq 0 ]]; then
    #auth2 is ready to use
    pingstatus=$(cat '/tmp/auth2_ping.json')
    pingstatus="${pingstatus//$'\n'/<br>}"
    pingstatus="${pingstatus//$'/'/\\/}"
    pingstatus=$(echo "${pingstatus}" | tr '"' "'" | tr '(' '<' | tr ')' '>' )
    pingstatus="<pre>${pingstatus}<\/pre>"

    #sed -i "0,/<td id='${HOSTNAME}status'>.*<\!--status-->/s//<td id='${HOSTNAME}status'>$(cat /tmp/auth2_ping.json)<\!--status-->/" ${serverinfofile}
    sed -i "0,/<td id='${HOSTNAME}status'>.*<\!--status-->/s//<td id='${HOSTNAME}status'>${pingstatus}<\!--status-->/" ${serverinfofile}
else
    sed -i "0,/<td id='${HOSTNAME}status'>.*<\!--status-->/s//<td id='${HOSTNAME}status'>Failed<\!--status-->/" ${serverinfofile}
fi
declare -a auth2pids;
declare -a cpuusages;
declare -a vsusages;
declare -a rsusages;
totalcpuusage=0;
totalvsusage=0;
totalrsusage=0;
for pid in $(ps -aux | grep "authome" | grep "python"|awk -F ' ' '{print $2}'); do
    auth2pids+=(${pid})
    IFS=',' read -ra DATA <<< $(printf  " %s,%s,%s" $(ps -o %cpu=,vsz=,rss= ${pid} | awk '{printf "%.2f %.0f %.0f",$1 ,$2,$3}'))
    cpuusages+=(${DATA[0]})
    vsusages+=($(perl -e "print ${DATA[1]} / 1024"))
    rsusages+=($(perl -e "print ${DATA[2]} / 1024"))
    totalcpuusage=$(perl -e "print ${totalcpuusage} + ${DATA[0]}")
    totalvsusage=$(( ${totalvsusage} + ${DATA[1]}))
    totalrsusage=$(( ${totalrsusage} + ${DATA[2]}))
done
totalvsusage=($(perl -e "print ${totalvsusage} / 1024"))
totalrsusage=($(perl -e "print ${totalrsusage} / 1024"))

resourceusage="<div class='summary' id='${HOSTNAME}'>Total CPU : $(printf %.1f ${totalcpuusage}) , Virutal Memory : $(printf %.2fM ${totalvsusage}) , Memory : $(printf %.2fM ${totalrsusage})<\/div><div id='${HOSTNAME}detail' class='detail'><ul>"

auth2processes=${#auth2pids[@]};
for (( i=0; i<${auth2processes}; i++ )); do 
    resourceusage="${resourceusage}<li>CPU : $(printf %.2f ${cpuusages[i]}) , Virtual Memory : $(printf %.2fM ${vsusages[i]}) , Memory : $(printf %.2fM ${rsusages[i]}) <\/li>"
done

resourceusage="${resourceusage}<\/ul><\/div>"

sed -i "0,/<td><div id='${HOSTNAME}resusage'>.*<\!--resusage-->/s//<td><div id='${HOSTNAME}resusage'>${resourceusage}<\!--resusage-->/" ${serverinfofile}

if [[ -f "/tmp/nextmonitortime" ]]; then
    nexttime=$(cat /tmp/nextmonitortime)
else
    nexttime=0
fi
#if [[ $(date '+%s') -ge ${nexttime} ]] ; then
if [[ $(date '+%s') -ge 0 ]] ; then
    message="<a href='javascript:void(0)' onclick='showdetailusage(\"${HOSTNAME}${nowseconds}\")' id='${HOSTNAME}${nowseconds}detaillink'>+<\/a> ${now} : "
    message="${message}<span class='summary' id='${HOSTNAME}${nowseconds}'>Total CPU : $(printf %.1f ${totalcpuusage}) , Virutal Memory : $(printf %.2fM ${totalvsusage}) , Memory : $(printf %.2fM ${totalrsusage})<\/span>"
    if [[ $status -eq 0 ]]; then
        message="${message} : Ping time=$(printf %.2f ${pingtime}) ms , Ping Result = Succeed "
    else
        message="${message} : Ping time=$(printf %.2f ${pingtime}) ms , Ping Result = Failed "
    fi
    message="${message} : <div style='display:none' id='${HOSTNAME}${nowseconds}detail' class='detail'><ul>"

    for (( i=0; i<${auth2processes}; i++ )); do 
        message="${message}<li>CPU : $(printf %.2f ${cpuusages[i]}) , Virtual Memory : $(printf %.2fM ${vsusages[i]}) , Memory : $(printf %.2fM ${rsusages[i]}) <\/li>"
    done
    if [[ $status -eq 0 ]]; then
        message="${message}<div>${pingstatus}<\/div><\/ul><\/div>"
    else
        message="${message}<\/ul><\/div>"
    fi

    sed -i "0,/<ol>/s//<ol>\n<li>${message}<\/li>/" ${monitoringfile}
    nextmonitortime=$(date -d "+${monitorInterval} seconds" "+%s")
    echo "${nextmonitortime}" > /tmp/nextmonitortime
fi

if [[ $status -eq 0 ]]; then
    #auth2 is ready to use
    sed -i "0,/<td id='${HOSTNAME}readytime'>.*<\!--readytime-->/s//<td id='${HOSTNAME}readytime'>${now}<\!--readytime-->/" ${serverinfofile}
fi
exit $status
