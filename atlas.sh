#!/usr/bin/env bash

set -euxo pipefail

readonly ATLAS_HOME="/usr/lib/atlas"
readonly ATLAS_ETC_DIR="/etc/atlas/conf"
readonly ATLAS_CONFIG="${ATLAS_ETC_DIR}/atlas-application.properties"
readonly INIT_SCRIPT="/usr/lib/systemd/system/atlas.service"

readonly ATLAS_ADMIN_USERNAME="$(/usr/share/google/get_metadata_value attributes/ATLAS_ADMIN_USERNAME || echo '')"
readonly ATLAS_ADMIN_PASSWORD_SHA256="$(/usr/share/google/get_metadata_value attributes/ATLAS_ADMIN_PASSWORD_SHA256 || echo '')"
readonly MASTER=$(/usr/share/google/get_metadata_value attributes/dataproc-master)
readonly ROLE=$(/usr/share/google/get_metadata_value attributes/dataproc-role)
readonly ADDITIONAL_MASTER=$(/usr/share/google/get_metadata_value attributes/dataproc-master-additional)

readonly KRB_REALM=$(sed -n '/^kerberos.realm=/ {s///p;q;}' /etc/google-dataproc/dataproc.properties)
readonly FQDN=$(hostname -d)
readonly KEYTAB_DIR="/etc/security/keytab"


function retry_command() {
  local retry_backoff=(1 1 2 3 5 8 13 21 34 55 89 144)
  local -a cmd=("$@")

  local update_succeeded=0
  for ((i = 0; i < ${#retry_backoff[@]}; i++)); do
    if eval "${cmd[@]}"; then
      update_succeeded=1
      break
    else
      local sleep_time=${retry_backoff[$i]}
      sleep "${sleep_time}"
    fi
  done

  if ! ((update_succeeded)); then
    echo "Final attempt of '${cmd[*]}'..."
    "${cmd[@]}"
  fi
}

function is_version_at_least() {
  local -r ver1="${1#v}.0.0.0.0"
  local -r ver2="${2#v}"
  local log
  log="$(mktemp)"

  dpkg --compare-versions "${ver1}" '>=' "${ver2}" >&"${log}"
  err_code="$?"

  if grep -C 10 -i warning "${log}"; then
    # The grep will show the specific warnings too
    echo 'Error: invalid versions compared'

    exit 1
  fi

  rm -f "${log}"
  return "${err_code}"
}

function is_version_lower() {
  local -r ver1="${1#v}"
  local -r ver2="${2#v}.0.0.0.0"
  local log
  log="$(mktemp)"

  dpkg --compare-versions "${ver1}" lt "${ver2}" >&"${log}"
  err_code="$?"

  if grep -C 10 -i warning "${log}"; then
    # The grep will show the specific warnings too
    echo 'Error: invalid versions compared'

    exit 1
  fi

  rm -f "${log}"
  return "${err_code}"
}

# Retries command until successful or up to a variable number of seconds.
# Sleeps for N seconds between the attempts.
function retry_constant_custom() {
  local -r max_retry_time="$1"
  local -r retry_delay="$2"
  local -r cmd=("${@:3}")

  local -r max_retries=$((max_retry_time / retry_delay))

  # Disable debug logs to not polute logs with retry attempts
  local last_log_timestamp="0"
  for ((i = 1; i < ${max_retries}; i++)); do
    if "${cmd[@]}"; then
      return 0
    fi

    local timestamp
    timestamp=$(date +%s)
    # Log at most once per 10 seconds
    if ((timestamp - last_log_timestamp > 10)); then
      last_log_timestamp="${timestamp}"
    fi
    sleep "${retry_delay}"
  done

  echo "Final attempt of '${cmd[*]}'..."
  set -x
  "${cmd[@]}"
}

function err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
  exit 1
}

# Waits for service on a given port to come up.
function wait_for_port() {
  local -r name="$1"
  local -r host="$2"
  local -r port="$3"
  local -r timeout="${4:-300}"

  # We only respect timeouts up to 1800 seconds (30 minutes).
  local -r capped_timeout=$((timeout > 3600 ? 3600 : timeout))

  retry_constant_custom \
    "${capped_timeout}" 10 nc -v -z -w 0 "${host}" "${port}"
  echo "Service up on host=${host} port=${port} name=${name}."
}

function check_prerequisites() {
  # check for Zookeeper
  wait_for_port "Zookeeper" localhost 2181

  # check for Solr
  cat >> /etc/default/solr << EOF
SOLR_JAVA_MEM="-Xms8192m -Xmx8192m"
EOF
  systemctl restart solr
  wait_for_port "Waiting for SOLR" localhost 8983

  curl 'http://localhost:8983/solr' || err 'Solr not found'

  if [[ -n "${ADDITIONAL_MASTER}" ]]; then
    # check for Kafka on HA
    ls /usr/lib/kafka &>/dev/null || err 'Kafka not found'
  fi
}

function configure_solr() {
  if [[ $(hostname) == "${MASTER}" ]]; then
    local curl_command=('curl' '-k' '--negotiate' '-u' ':')
    "${curl_command[@]}" "http://localhost:8983/solr"

    local login
    if ls /usr/sbin/kadmin.local &>/dev/null; then
      solrconfig="export SOLR_INCLUDE=/etc/default/solr; "
    else
      solrconfig=""
    fi

    # configure Solr only on the one actual Master node
    runuser -l solr -s /bin/bash -c "${solrconfig}/usr/lib/solr/bin/solr create -c vertex_index -d ${ATLAS_ETC_DIR}/solr -shards 3"
    runuser -l solr -s /bin/bash -c "${solrconfig}/usr/lib/solr/bin/solr create -c edge_index -d ${ATLAS_ETC_DIR}/solr -shards 3"
    runuser -l solr -s /bin/bash -c "${solrconfig}/usr/lib/solr/bin/solr create -c fulltext_index -d ${ATLAS_ETC_DIR}/solr -shards 3"
  fi
}

function create_atlas_keytab(){
  if ls /usr/sbin/kadmin.local &>/dev/null; then
    kadmin.local -q "addprinc -randkey atlas/${FQDN}@${KRB_REALM}"
    kadmin.local -q "ktadd -k ${KEYTAB_DIR}/atlas.service.keytab atlas/${FQDN}@${KRB_REALM}"
    kadmin.local -q "ktadd -k ${KEYTAB_DIR}/atlas.service.keytab HTTP/${FQDN}@${KRB_REALM}"
  fi

}

function configure_atlas() {
  local zk_quorum
  zk_quorum="localhost:2181"
  local zk_url_for_solr
  zk_url_for_solr="$(echo "${zk_quorum}" | sed 's/:2181/:2181\/solr/g')"

  local cluster_name
  cluster_name=$(/usr/share/google/get_metadata_value attributes/dataproc-cluster-name)

  # Symlink HBase conf dir
  mkdir "${ATLAS_HOME}/hbase"
  ln -s "/etc/hbase/conf" "${ATLAS_HOME}/hbase/conf"

  # Configure Atlas
  sed -i "s/atlas.graph.storage.hostname=.*/#atlas.graph.storage.hostname=/" ${ATLAS_CONFIG}
  sed -i "s/atlas.graph.storage.hbase.table=.*/atlas.graph.storage.hbase.table=atlas/" ${ATLAS_CONFIG}
  sed -i "s/atlas.rest.address=.*/atlas.rest.address=http:\/\/localhost:21000/" ${ATLAS_CONFIG}
  sed -i "s/atlas.audit.hbase.zookeeper.quorum=.*/#atlas.audit.hbase.zookeeper.quorum=/" ${ATLAS_CONFIG}


  if [[ -n "${ADDITIONAL_MASTER}" ]]; then
    # Configure HA
    sed -i "s/atlas.server.ha.enabled=.*/atlas.server.ha.enabled=true/" ${ATLAS_CONFIG}
    sed -i "s/atlas.server.ha.zookeeper.connect=.*/atlas.server.ha.zookeeper.connect=${zk_quorum}/" ${ATLAS_CONFIG}
    sed -i "s/atlas.graph.index.search.solr.wait-searcher=.*/#atlas.graph.index.search.solr.wait-searcher=.*/" ${ATLAS_CONFIG}
    sed -i "s|atlas.graph.index.search.solr.zookeeper-url=.*|atlas.graph.index.search.solr.zookeeper-url=${zk_url_for_solr}|" ${ATLAS_CONFIG}

    cat <<EOF >>${ATLAS_CONFIG}
atlas.server.ids=m0,m1,m2
atlas.server.address.m0=${cluster_name}-m-0:21000
atlas.server.address.m1=${cluster_name}-m-1:21000
atlas.server.address.m2=${cluster_name}-m-2:21000
atlas.server.ha.zookeeper.zkroot=/apache_atlas
atlas.client.ha.retries=4
atlas.client.ha.sleep.interval.ms=5000
EOF
  else

    # Disable Solr Cloud
    sed -i "s/atlas.graph.index.search.solr.mode=cloud/#atlas.graph.index.search.solr.mode=cloud/" ${ATLAS_CONFIG}
    sed -i "s/atlas.graph.index.search.solr.zookeeper-url=.*/#atlas.graph.index.search.solr.zookeeper-url=.*/" ${ATLAS_CONFIG}
    sed -i "s/atlas.graph.index.search.solr.zookeeper-connect-timeout=.*/#atlas.graph.index.search.solr.zookeeper-connect-timeout=.*/" ${ATLAS_CONFIG}
    sed -i "s/atlas.graph.index.search.solr.zookeeper-session-timeout=.*/#atlas.graph.index.search.solr.zookeeper-session-timeout=.*/" ${ATLAS_CONFIG}
    sed -i "s/atlas.graph.index.search.solr.wait-searcher=.*/#atlas.graph.index.search.solr.wait-searcher=.*/" ${ATLAS_CONFIG}

    # Enable Solr HTTP
    sed -i "s/#atlas.graph.index.search.solr.mode=http/atlas.graph.index.search.solr.mode=http/" ${ATLAS_CONFIG}
    sed -i "s/#atlas.graph.index.search.solr.http-urls=.*/atlas.graph.index.search.solr.http-urls=http:\/\/localhost:8983\/solr/" ${ATLAS_CONFIG}

  fi

  # Override default admin username:password
  if [[ -n "${ATLAS_ADMIN_USERNAME}" && -n "${ATLAS_ADMIN_PASSWORD_SHA256}" ]]; then
    sed -i "s/admin=.*/${ATLAS_ADMIN_USERNAME}=ROLE_ADMIN::${ATLAS_ADMIN_PASSWORD_SHA256}/" \
      "${ATLAS_HOME}/conf/users-credentials.properties"
  fi


  # Configure to use local Kafka
  if ls /usr/lib/kafka &>/dev/null; then
    echo "Running atlas kafka modifications"
    sed -i "s/atlas.notification.embedded=.*/atlas.notification.embedded=false/" ${ATLAS_CONFIG}
    sed -i "s/atlas.kafka.zookeeper.connect=.*/atlas.kafka.zookeeper.connect=${zk_quorum}/" ${ATLAS_CONFIG}
    sed -i "s/atlas.kafka.bootstrap.servers=.*/atlas.kafka.bootstrap.servers=$(hostname -f):9092/" ${ATLAS_CONFIG}
  else
    # in a default setup it uses embedded kafka and zookeeper for notifications, if a 
    # full version is required, please set this to true and install kafka in the cluster
    # NOTE: Disabling notifications since we are not installing kafka
    sed -i "s/atlas.notification.embedded=.*/atlas.notification.embedded=false/" ${ATLAS_CONFIG}
    #ignore kafka notifications for now
    sed -i 's/<priority value="warn"\/>/<priority value="error"\/>/' ${ATLAS_ETC_DIR}/atlas-log4j.xml
  fi

}

function replace_spring_jars(){
  local dest="/usr/lib/atlas/server/webapp/atlas/WEB-INF/lib/"
  local site="https://repo1.maven.org/maven2/org"
  local fwk="springframework"

  local src="${site}/${fwk}"

  rm "${dest}"*spring*

  wget "${src}"/spring-aop/4.3.17.RELEASE/spring-aop-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-beans/4.3.17.RELEASE/spring-beans-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-context/4.3.17.RELEASE/spring-context-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-core/4.3.17.RELEASE/spring-core-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-expression/4.3.17.RELEASE/spring-expression-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-test/4.3.17.RELEASE/spring-test-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-tx/4.3.17.RELEASE/spring-tx-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-web/4.3.17.RELEASE/spring-web-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/spring-webmvc/4.3.17.RELEASE/spring-webmvc-4.3.17.RELEASE.jar -P "${dest}"
  wget "${src}"/ldap/spring-ldap-core/2.3.2.RELEASE/spring-ldap-core-2.3.2.RELEASE.jar -P "${dest}"
  wget "${src}"/security/spring-security-config/4.2.6.RELEASE/spring-security-config-4.2.6.RELEASE.jar -P "${dest}"
  wget "${src}"/security/spring-security-core/4.2.6.RELEASE/spring-security-core-4.2.6.RELEASE.jar -P "${dest}"
  wget "${src}"/security/spring-security-ldap/4.2.6.RELEASE/spring-security-ldap-4.2.6.RELEASE.jar -P "${dest}"
  wget "${src}"/security/spring-security-web/4.2.6.RELEASE/spring-security-web-4.2.6.RELEASE.jar -P "${dest}"

  src="https://repo1.maven.org/maven2/com/sun/jersey/contribs/jersey-spring"
  wget "${src}"/1.19.4/jersey-spring-1.19.4.jar  -P "${dest}"
}

function add_bigtable_lib(){
  local bigtable_version="2.12.0"
  local dest="/usr/lib/atlas/server/webapp/atlas/WEB-INF/lib/"
  local site="https://repo1.maven.org/maven2/com/google/cloud/bigtable/bigtable-hbase-2.x-shaded/${bigtable_version}/bigtable-hbase-2.x-shaded-${bigtable_version}.jar"

  wget "${site}" -P "${dest}"
}

function start_atlas() {
  cat <<EOF >${INIT_SCRIPT}
[Unit]
Description=Apache Atlas

[Service]
Type=forking
ExecStart=${ATLAS_HOME}/bin/atlas_start.py
ExecStop=${ATLAS_HOME}/bin/atlas_stop.py
RemainAfterExit=yes
TimeoutSec=10m

[Install]
WantedBy=multi-user.target
EOF
  chmod a+rw ${INIT_SCRIPT}
  systemctl enable atlas

  mkdir -p /usr/lib/atlas/server/webapp/atlas
  pushd .
  cd /usr/lib/atlas/server/webapp/atlas
  jar -xvf ../atlas.war
  popd

  replace_spring_jars
  add_bigtable_lib

  # See: https://atlas.apache.org/1.0.0/Atlas-Authentication.html
  if ls /usr/sbin/kadmin.local &>/dev/null; then
    sed -i '/ATLAS_CONFIG_OPTS="-Datlas.conf=%s"/c\ATLAS_CONFIG_OPTS="-Datlas.conf=%s -Djava.security.auth.login.config=/usr/lib/solr/server/solr/jaas-client.conf"' /usr/lib/atlas/bin/atlas_start.py
    sed -i -e '/atlas\.authentication\.method\.kerberos=/ s/=.*/=true/' /usr/lib/atlas/conf/atlas-application.properties
  fi
  sed -i -e '/atlas\.authentication\.method\.file=/ s/=.*/=true/' /usr/lib/atlas/conf/atlas-application.properties


  # if it is kerberos enabled
  if ls /usr/sbin/kadmin.local &>/dev/null; then
    cat >> /usr/lib/atlas/conf/atlas-application.properties << EOF
atlas.authentication.method.kerberos.principal=atlas/${FQDN}@${KRB_REALM}
atlas.authentication.method.kerberos.keytab=${KEYTAB_DIR}/atlas.service.keytab
atlas.authentication.method.kerberos.name.rules=RULE:[1:\$1](.*)s/(.*)/\$1/g  RULE:[2:\$1](.*)s/(.*)/\$1/g  DEFAULT
atlas.authentication.method.kerberos.token.validity=3600
atlas.authentication.method.kerberos.support.keytab.browser.login=true
EOF
  fi

  fix_gremlin_core_lib

  systemctl start atlas
}

function wait_for_atlas_to_start() {
  # atlas start script exits prematurely, before atlas actually starts
  # thus wait up to 10 minutes until atlas is fully working
  wait_for_port "Atlas web server test" localhost 21000 3600
  echo "port successful"
  for ((i = 0; i < 120; i++)); do
    if curl localhost:21000/api/atlas/admin/status; then
      return 0
    fi
    sleep 30
  done
  return 1
}

function wait_for_atlas_becomes_active_or_passive() {
  for ((i = 0; i < 60; i++)); do
    # public check, but some username:password has to be given
    if status=$(python2 ${ATLAS_HOME}/bin/atlas_admin.py -u doesnt:matter -status 2>/dev/null); then
      if [[ ${status} == 'ACTIVE' || ${status} == 'PASSIVE' ]]; then
        return 0
      fi
    fi
    sleep 10
  done
  return 1
}

function enable_hive_hook() {
  bdconfig set_property \
    --name 'hive.exec.post.hooks' \
    --value 'org.apache.atlas.hive.hook.HiveHook' \
    --configuration_file '/etc/hive/conf/hive-site.xml' \
    --clobber

  echo "export HIVE_AUX_JARS_PATH=${ATLAS_HOME}/hook/hive" >>/etc/hive/conf/hive-env.sh
  ln -s ${ATLAS_CONFIG} /etc/hive/conf/
}

function enable_hbase_hook() {
  bdconfig set_property \
    --name 'hbase.coprocessor.master.classes' \
    --value 'org.apache.atlas.hbase.hook.HBaseAtlasCoprocessor' \
    --configuration_file '/usr/lib/hbase/conf/hbase-site.xml' \
    --clobber

  ln -s ${ATLAS_HOME}/hook/hbase/* /usr/lib/hbase/lib/
  ln -s ${ATLAS_CONFIG} /usr/lib/hbase/conf/
}

function enable_sqoop_hook() {
  if [[ ! -f /usr/lib/sqoop ]]; then
    echo 'Sqoop not found, not configuring hook'
    return
  fi

  if [[ ! -f /usr/lib/sqoop/conf/sqoop-site.xml ]]; then
    cp /usr/lib/sqoop/conf/sqoop-site-template.xml /usr/lib/sqoop/conf/sqoop-site.xml
  fi

  bdconfig set_property \
    --name 'sqoop.job.data.publish.class' \
    --value 'org.apache.atlas.sqoop.hook.SqoopHook' \
    --configuration_file '/usr/lib/sqoop/conf/sqoop-site.xml' \
    --clobber

  ln -s ${ATLAS_HOME}/hook/sqoop/* /usr/lib/sqoop/lib
  ln -s ${ATLAS_CONFIG} /usr/lib/sqoop/conf
}

function enable_bigtable() {
  echo "atlas.graph.storage.hbase.ext.google.bigtable.instance.id=atlas-bigtable-demo" >> ${ATLAS_CONFIG}
  echo "atlas.graph.storage.hbase.ext.google.bigtable.project.id=YOUR_PORJECT_ID" >> ${ATLAS_CONFIG}
  echo "atlas.graph.storage.hbase.ext.hbase.client.connection.impl=com.google.cloud.bigtable.hbase2_x.BigtableConnection" >> ${ATLAS_CONFIG}
  echo "atlas.server.run.setup.on.start=false" >> ${ATLAS_CONFIG}
  
  pushd .
  cd /usr/lib/atlas/hbase
  ln -sf /usr/lib/hbase/conf/ conf
  popd
  
}

function fix_gremlin_core_lib() {

  local gremlin_core_version="3.3.3"
  local dest="/usr/lib/atlas/server/webapp/atlas/WEB-INF/lib/"
  local site="https://repo1.maven.org/maven2/org/apache/tinkerpop/gremlin-core/${gremlin_core_version}/gremlin-core-${gremlin_core_version}.jar"

  rm /usr/lib/atlas/server/webapp/atlas/WEB-INF/lib/gremlin-core-3.5.6.jar

  wget "${site}" -P "${dest}"
}


function main() {
  if [[ "${ROLE}" == 'Master' ]]; then
    check_prerequisites
    create_atlas_keytab
    retry_command "apt-get install -q -y atlas"
    configure_solr
    configure_atlas
    enable_hive_hook
    enable_hbase_hook
    enable_sqoop_hook
    enable_bigtable
    start_atlas
    wait_for_atlas_to_start
    wait_for_atlas_becomes_active_or_passive
  fi
}

main


