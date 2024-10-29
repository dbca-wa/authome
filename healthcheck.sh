#!/bin/bash
AUTH2_DOMAIN=auth2-dev.dbca.gov.au
PING_TIMEOUT=1
MONITOR_INTERVAL=60
AUTH2_MONITORING_DIR=~/projects/authome/monitoring
AUTH2_CLUSTERID="AUTH2_01"
PORT=8070
EXPIREDAYS=2
SERVICEID=${HOSTNAME}
SERVICEID="AUTH02_003"


nowseconds=$(date '+%s')
now=$(date '+%Y-%m-%d %H:%M:%S')
today=$(date '+%Y-%m-%d')

if [[ "${AUTH2_CLUSTERID}" == "" ]]; then
    monitoringhome="${AUTH2_MONITORING_DIR}/auth2/standalone"
    mkdir -p "${AUTH2_MONITORING_DIR}/auth2/standalone/${SERVICEID}/liveness"
    serverinfofile="${AUTH2_MONITORING_DIR}/auth2/standalone/${SERVICEID}/serverinfo.html"
    livenessfooterfile="${AUTH2_MONITORING_DIR}/auth2/standalone/${SERVICEID}/livenessfooter.html"
    latestreadytimefile="${AUTH2_MONITORING_DIR}/auth2/standalone/${SERVICEID}/latestreadytime"
    livenessfile="${AUTH2_MONITORING_DIR}/auth2/standalone/${SERVICEID}/liveness/${today}.html"
else
    monitoringhome="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}"
    mkdir -p "${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${SERVICEID}/liveness"
    serverinfofile="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${SERVICEID}/serverinfo.html"
    livenessfooterfile="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${SERVICEID}/livenessfooter.html"
    latestreadytimefile="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${SERVICEID}/latestreadytime"
    livenessfile="${AUTH2_MONITORING_DIR}/auth2/${AUTH2_CLUSTERID}/${SERVICEID}/liveness/${today}.html"
fi

serverinfochanges=""

if [[ ! -f "${serverinfofile}" ]]; then
    echo -e "<tr>\n<td id='${SERVICEID}'>${SERVICEID}</td>\n<td id='${SERVICEID}readytime'></td>\n<td id='${SERVICEID}heartbeat'>${now}</td>\n<td id='${SERVICEID}processingtime'></td>\n<td id='${SERVICEID}status'>\n<!--start_status-->\n<!--end_status-->\n</td>\n<td id='${SERVICEID}resusage'>\n</td>\n<td>\n<ul id='${SERVICEID}monitoring'>\n</ul>\n</td>\n</tr>" > "${serverinfofile}"
    cp /home/rockyc/projects/auth2_chart/static/auth2livenessfooter.html ${livenessfooterfile}
else
    serverinfochanges="-e \"s/<td id='${SERVICEID}heartbeat'>.*/<td id='${SERVICEID}heartbeat'>${now}<\/td>/\" "
fi
if [[ ! -f "${livenessfile}" ]]; then
    cp /home/rockyc/projects/auth2_chart/static/auth2liveness.html "${livenessfile}"
    chmod 775 "${livenessfile}"
    newlivenessfile=1
    if [[ "${AUTH2_CLUSTERID}" == "" ]]; then
        serverinfochanges="${serverinfochanges} -e \"s/<ul id='${SERVICEID}monitoring'>/<ul id='${SERVICEID}monitoring'>\n<li><a href='\/admin\/liveness\/${SERVICEID}\/${today}.html'>${today}<\/a><\/li>/\" "
        sed -i -e "0,/<title[^<]*<\/title>/s//<title>Auth2 server($SERVICEID) Liveness Data<\/title>/" -e "0,/<span id=\"breadcrumb1\">[^<]*<\/span>/s//<span id=\"breadcrumb1\"><a href=\"\/admin\/auth2status\">Auth2 Server Status<\/a><\/span>/" -e "0,/<span id=\"breadcrumb2\">[^<]*<\/span>/s//<span id=\"breadcrumb2\">${today}<\/span>/" -e "0,/<span id=\"breadcrumb2\">[^<]*<\/span>/s//<span id=\"breadcrumb2a\">${SERVICEID}<\/span> \&rsaquo; <span id=\"breadcrumb2b\">${today}<\/span>/" ${livenessfile}
    else
        serverinfochanges="${serverinfochanges} -e \"s/<ul id='${SERVICEID}monitoring'>/<ul id='${SERVICEID}monitoring'>\n<li><a href='\/admin\/liveness\/${AUTH2_CLUSTERID}\/${SERVICEID}\/${today}.html'>${today}<\/a><\/li>/\""
        sed -i -e "0,/<title[^<]*<\/title>/s//<title>Auth2 cluster(${AUTH2_CLUSTERID}:$SERVICEID) Liveness Data<\/title>/" -e "0,/<span id=\"breadcrumb1\">[^<]*<\/span>/s//<span id=\"breadcrumb1a\">Auth2 Cluster Status<\/span> \&rsaquo; <span id=\"breadcrumb1b\"><a href=\"\/admin\/auth2status\/${AUTH2_CLUSTERID}\">${AUTH2_CLUSTERID}<\/a><\/span>/" -e "0,/<span id=\"breadcrumb2\">[^<]*<\/span>/s//<span id=\"breadcrumb2a\">${SERVICEID}<\/span> \&rsaquo; <span id=\"breadcrumb2b\">${today}<\/span>/" ${livenessfile}
    fi
    #manage the monitoring files
    earliest_date=$(date --date="${today}-${EXPIREDAYS} days")
    earliest_seconds=$(date --date="${earliest_date}" "+%s")
    for serviceid in $(ls "${monitoringhome}" ); do 
        if [[ -d "${monitoringhome}/${serviceid}/liveness" ]]; then
            serverexpired=1
            for d in $(ls "${monitoringhome}/${serviceid}/liveness" ); do 
                logdate=${d%.html*}
                logdate=$(date --date="${logdate}")
                logdate_seconds=$(date --date="${logdate}" "+%s")
                logdate=$(date --date="${logdate}" "+%Y-%m-%d")
                if [[ ${logdate_seconds} -lt ${earliest_seconds} ]]; then
                    #remove the expired monitoring file from serverinfofile
                    #echo "The monitoring file(${d}.html) of auth2 server(${serviceid}) is expired"
                    sed -i "/${logdate}<\/a><\/li>/d" "${monitoringhome}/${serviceid}/serverinfo.html"
                    if [[ $? -eq 0 ]]; then
                        rm -f "${monitoringhome}/${serviceid}/liveness/${d}"
                    fi
                else
                    serverexpired=0
                    break
                fi
            done
            if [[ ${serverexpired} -eq 1 ]]; then
                #all monitoring files of this service are expired
                #remove service from serverinfofile
                #echo "The auth2 server(${serviceid}) is expired"
                rm -rf "${monitoringhome}/${serviceid}"
            fi
        fi
    done;
else
  newlivenessfile=0
fi
starttime=$(date '+%s.%N')
wget --tries=1 --header="Host:${AUTH2_DOMAIN}" --timeout=${PING_TIMEOUT} http://127.0.0.1:${PORT}/ping -o /dev/null -O /tmp/auth2_ping.json
status=$?
endtime=$(date '+%s.%N')
pingtime=$(perl -e "print (${endtime} - ${starttime}) * 1000")

serverinfochanges="${serverinfochanges} -e \"s/<td id='${SERVICEID}processingtime'>.*/<td id='${SERVICEID}processingtime'>$(printf %.2f ${pingtime}) ms<\/td>/\" "
#set auth2 starttime
if [[ $status -eq 0 ]]; then
    #auth2 is ready to use
    echo "${nowseconds}" > ${latestreadytimefile}
    message="<a href='javascript:void(0)' onclick='showdetailusage(\\\"${SERVICEID}\\\")' id='${SERVICEID}detaillink'>+<\/a>Succeed"
    message="${message} <div style='display:none' id='${SERVICEID}detail' class='detail'><pre>"

    serverinfochanges="${serverinfochanges} -e \"/<!--start_status-->/,/<!--end_status-->/d\" -e \"/<td id='${SERVICEID}status'>/a <!--start_status-->\n${message}\" -e \"/<td id='${SERVICEID}status'>/r /tmp/auth2_ping.json\" -e \"/<td id='${SERVICEID}status'>/a </pre><\/div>\n<!--end_status-->\""
else
    serverinfochanges="${serverinfochanges} -e \"/<!--start_status-->/,/<!--end_status-->/d\" -e \"s/<td id='${SERVICEID}status'>.*/<td id='${SERVICEID}status'>\n<!--start_status-->\nFailed\n<!--end_status-->/\" "
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

auth2processes=${#auth2pids[@]};

resourceusage="<div class='summary' id='${SERVICEID}'>Processes : ${auth2processes} , Total CPU : $(printf %6.2f%% ${totalcpuusage}) , Virutal Memory : $(printf %8.2fM ${totalvsusage}) , Memory : $(printf %8.2fM ${totalrsusage})<\/div><div id='${SERVICEID}detail' class='detail'><ul>"

for (( i=0; i<${auth2processes}; i++ )); do 
    resourceusage="${resourceusage}<li>CPU : $(printf %6.2f%% ${cpuusages[i]}) , Virtual Memory : $(printf %8.2fM ${vsusages[i]}) , Memory : $(printf %8.2fM ${rsusages[i]}) <\/li>"
done

resourceusage="${resourceusage}<\/ul><\/div>"

serverinfochanges="${serverinfochanges} -e \"s/<td id='${SERVICEID}resusage'>.*/<td id='${SERVICEID}resusage'>${resourceusage}/\" "
if [[ ${newlivenessfile} -eq 1 ]]; then
    nexttime=0
elif [[ -f "/tmp/nextmonitortime" ]]; then
    nexttime=$(cat /tmp/nextmonitortime)
else
    nexttime=0
fi
nexttime=0
if [[ $(date '+%s') -ge ${nexttime} ]] ; then
    message="<a href='javascript:void(0)' onclick='showdetailusage(\"${SERVICEID}${nowseconds}\")' id='${SERVICEID}${nowseconds}detaillink'>+</a>"
    message="${message}<span class='summary' id='${SERVICEID}${nowseconds}'> ${now} : Processes : ${auth2processes} , Total CPU : $(printf %6.2f%% ${totalcpuusage}) , Virutal Memory : $(printf %8.2fM ${totalvsusage}) , Memory : $(printf %8.2fM ${totalrsusage})"
    if [[ $status -eq 0 ]]; then
        message="${message} : Ping time=$(printf %7.3f ${pingtime}) ms , Ping Result = Succeed "
    else
        message="${message} : Ping time=$(printf %7.3f ${pingtime}) ms , Ping Result = Failed "
    fi
    message="${message}</span> <div style='display:none' id='${SERVICEID}${nowseconds}detail' class='detail'><ul>"

    for (( i=0; i<${auth2processes}; i++ )); do 
        message="${message}<li>CPU : $(printf %6.2f%% ${cpuusages[i]}) , Virtual Memory : $(printf %8.2fM ${vsusages[i]}) , Memory : $(printf %8.2fM ${rsusages[i]}) </li>"
    done
    if [[ $status -eq 0 ]]; then
        message="${message}</ul><div><pre>$(cat /tmp/auth2_ping.json)</pre></div></div>"
    else
        message="${message}</ul></div>"
    fi

    echo "<li>${message}</li>" >> ${livenessfile}
    nextmonitortime=$(date -d "$(date -d "${now}")+${MONITOR_INTERVAL} seconds" "+%s")
    echo "${nextmonitortime}" > /tmp/nextmonitortime
fi

if [[ "${serverinfochanges}" != "" ]]; then
    eval "sed -i ${serverinfochanges} ${serverinfofile}"
fi
if [[ ${status} -eq 0 ]]; then
    #auth2 is ready to use
    sed -i "s/<td id='${SERVICEID}readytime'>.*/<td id='${SERVICEID}readytime'>${now}<\/td>/" ${serverinfofile}
fi
exit ${status}
