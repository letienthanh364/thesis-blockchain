#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
shift || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${APP_DIR}/.." && pwd)"
FABRIC_BIN_DIR="${REPO_ROOT}/bin"
RUNTIME_DIR="${SCRIPT_DIR}/runtime"
LOG_DIR="${RUNTIME_DIR}/logs"
PID_DIR="${RUNTIME_DIR}/pids"
DATA_DIR="${RUNTIME_DIR}/data"
CONFIG_SRC="${APP_DIR}/config"
CONFIG_DIR="${RUNTIME_DIR}/config"
BUILD_DIR="${RUNTIME_DIR}/bin"
CHANNEL_ARTIFACTS_DIR="${APP_DIR}/channel-artifacts"
CHAINCODE_DIR="${APP_DIR}/chaincode"
SYSTEM_GENESIS_DIR="${APP_DIR}/system-genesis-block"
ORG_DIR="${APP_DIR}/organizations"
ORDERER_DIR="${ORG_DIR}/ordererOrganizations/nebula.com/orderers/orderer.nebula.com"
PEER_ORG_DIR="${ORG_DIR}/peerOrganizations/org1.nebula.com"
DATA_FILE="${APP_DIR}/data/trainers.json"
# Network connections use localhost; FQDNs are kept for identity and cert paths.
FABRIC_RESOLVE_HOST="${FABRIC_RESOLVE_HOST:-localhost}"

export PATH="${FABRIC_BIN_DIR}:${PATH}"

err() {
  echo "[process-runner] $1" >&2
}

die() {
  err "$1"
  exit 1
}

ensure_prereqs() {
  for bin in orderer peer go; do
    if ! command -v "${bin}" >/dev/null 2>&1; then
      die "required binary '${bin}' not found in PATH (${PATH}). Run ./install-fabric.sh binary and ensure Go is installed."
    fi
  done

  for dir in "${ORG_DIR}" "${CHANNEL_ARTIFACTS_DIR}" "${SYSTEM_GENESIS_DIR}"; do
    if [ ! -d "${dir}" ]; then
      die "missing ${dir}. Generate MSP material and artifacts before starting the process stack."
    fi
  done
}

listening_pids() {
  local port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -t -nP -iTCP:${port} -sTCP:LISTEN 2>/dev/null || true
  else
    echo ""
  fi
}

kill_conflicting_listeners() {
  local port=$1
  local label=$2
  local signature=$3
  local killed=0
  local pids
  pids=$(listening_pids "${port}")
  [ -z "${pids}" ] && return 0
  for pid in ${pids}; do
    local cmd
    cmd=$(ps -p "${pid}" -o command= 2>/dev/null || true)
    if [[ "${cmd}" == *"${signature}"* ]]; then
      echo "[process-runner] stopping leftover ${label} (pid ${pid})"
      kill "${pid}" >/dev/null 2>&1 || true
      killed=1
    else
      err "port ${port} in use by PID ${pid} (${cmd}). Stop it manually or change the port before running the process stack."
      exit 1
    fi
  done
  if [ "${killed}" -eq 1 ]; then
    for _ in {1..15}; do
      if [ -z "$(listening_pids "${port}")" ]; then
        return 0
      fi
      sleep 1
    done
    err "port ${port} is still busy after terminating leftover ${label} process(es)"
    exit 1
  fi
}

prepare_ports() {
  local checks=(
    "7050 orderer orderer"
    "7051 peer0 peer"
    "8051 peer1 peer"
    "9051 peer2 peer"
    "9000 api-gateway api-gateway"
  )
  for check in "${checks[@]}"; do
    IFS=" " read -r port label sig <<<"${check}"
    kill_conflicting_listeners "${port}" "${label}" "${sig}"
  done
}

prepare_runtime() {
  mkdir -p "${LOG_DIR}" "${PID_DIR}" "${DATA_DIR}" "${BUILD_DIR}"
  mkdir -p "${APP_DIR}/data"
  touch "${DATA_FILE}"

  rm -rf "${CONFIG_DIR}"
  mkdir -p "${CONFIG_DIR}"
  cp -R "${CONFIG_SRC}/." "${CONFIG_DIR}/"

  local builder_base="${APP_DIR}/external_builders"
  if [ -d "${builder_base}" ]; then
    perl -0pi -e "s|path: .*/external_builders/golang|path: ${builder_base}/golang|g" "${CONFIG_DIR}/core.yaml"
    perl -0pi -e "s|path: .*/external_builders/node|path: ${builder_base}/node|g" "${CONFIG_DIR}/core.yaml"
  fi

  local orderer_tls_ca="${ORDERER_DIR}/msp/tlscacerts/tlsca.nebula.com-cert.pem"
  perl -0pi -e "s|addressOverrides:\\n|addressOverrides:\\n          - from: orderer.nebula.com:7050\\n            to: ${FABRIC_RESOLVE_HOST}:7050\\n            caCertsFile: ${orderer_tls_ca}\\n|g" "${CONFIG_DIR}/core.yaml"

  export FABRIC_CFG_PATH="${CONFIG_DIR}"
}

pid_file_for() {
  echo "${PID_DIR}/$1.pid"
}

log_file_for() {
  echo "${LOG_DIR}/$1.log"
}

component_running() {
  local name=$1
  local pid_file
  pid_file=$(pid_file_for "${name}")
  if [ -f "${pid_file}" ]; then
    local pid
    pid=$(cat "${pid_file}")
    if kill -0 "${pid}" >/dev/null 2>&1; then
      return 0
    fi
    rm -f "${pid_file}"
  fi
  return 1
}

start_process() {
  local name=$1
  shift
  if component_running "${name}"; then
    die "${name} is already running (pid $(cat "$(pid_file_for "${name}")")). Run '$0 stop' first."
  fi
  local env_vars=()
  while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then
      shift
      break
    fi
    env_vars+=("$1")
    shift
  done
  local cmd=("$@")
  local pid_file
  pid_file=$(pid_file_for "${name}")
  local log_file
  log_file=$(log_file_for "${name}")
  (
    for kv in "${env_vars[@]}"; do
      export "$kv"
    done
    exec "${cmd[@]}"
  ) >>"${log_file}" 2>&1 &
  local pid=$!
  echo "${pid}" > "${pid_file}"
  echo "[process-runner] started ${name} (pid ${pid})"
}

stop_component() {
  local name=$1
  local pid_file
  pid_file=$(pid_file_for "${name}")
  if [ ! -f "${pid_file}" ]; then
    return
  fi
  local pid
  pid=$(cat "${pid_file}")
  if kill -0 "${pid}" >/dev/null 2>&1; then
    echo "[process-runner] stopping ${name} (pid ${pid})"
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
  rm -f "${pid_file}"
}

wait_for_port() {
  local host=$1
  local port=$2
  local label=$3
  for _ in {1..60}; do
    if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "timed out waiting for ${label} on ${host}:${port}"
}

build_gateway_binary() {
  pushd "${APP_DIR}/api" >/dev/null
  go build -o "${BUILD_DIR}/api-gateway" ./cmd/gateway
  popd >/dev/null
}

gateway_env() {
  load_env_file
  local org_crypto="${PEER_ORG_DIR}"
  local orderer_tls="${ORDERER_DIR}/msp/tlscacerts/tlsca.nebula.com-cert.pem"
  echo "FABRIC_CHANNEL=${FABRIC_CHANNEL:-nebulachannel}"
  echo "FABRIC_CHAINCODE=${FABRIC_CHAINCODE:-gateway}"
  echo "MSP_ID=${MSP_ID:-Org1MSP}"
  echo "ORG_CRYPTO_PATH=${org_crypto}"
  echo "ADMIN_IDENTITY=${ADMIN_IDENTITY:-Admin@org1.nebula.com}"
  echo "ORDERER_ENDPOINT=${ORDERER_ENDPOINT:-${FABRIC_RESOLVE_HOST}:7050}"
  echo "ORDERER_TLS_HOSTNAME_OVERRIDE=${ORDERER_TLS_HOSTNAME_OVERRIDE:-orderer.nebula.com}"
  echo "ORDERER_TLS_CA=${orderer_tls}"
  echo "ORG_DOMAIN=${ORG_DOMAIN:-org1.nebula.com}"
  echo "PEER_ENDPOINTS=${PEER_ENDPOINTS:-peer0=${FABRIC_RESOLVE_HOST}:7051,peer1=${FABRIC_RESOLVE_HOST}:8051,peer2=${FABRIC_RESOLVE_HOST}:9051}"
  echo "DEFAULT_PEER=${DEFAULT_PEER:-peer0}"
  echo "TRAINER_DB_PATH=${DATA_FILE}"
  echo "AUTH_JWT_SECRET=${AUTH_JWT_SECRET}"
  echo "ADMIN_PUBLIC_KEY=${ADMIN_PUBLIC_KEY}"
  echo "FABRIC_CFG_PATH=${FABRIC_CFG_PATH}"
}

load_env_file() {
  local env_file="${APP_DIR}/.env"
  if [ -f "${env_file}" ]; then
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
  fi
  if [ -z "${AUTH_JWT_SECRET:-}" ] || [ -z "${ADMIN_PUBLIC_KEY:-}" ]; then
    die "AUTH_JWT_SECRET and ADMIN_PUBLIC_KEY must be set (export them or configure api-gateway/.env)"
  fi
}

start_orderer() {
  local tls_dir="${ORDERER_DIR}/tls"
  local ledger_dir="${DATA_DIR}/orderer"
  local raft_dir="${ledger_dir}/etcdraft"
  local wal_dir="${raft_dir}/wal"
  local snap_dir="${raft_dir}/snapshot"
  mkdir -p "${ledger_dir}"
  mkdir -p "${wal_dir}" "${snap_dir}"
  start_process orderer \
    "FABRIC_CFG_PATH=${FABRIC_CFG_PATH}" \
    "ORDERER_GENERAL_LISTENADDRESS=0.0.0.0" \
    "ORDERER_GENERAL_LISTENPORT=7050" \
    "ORDERER_GENERAL_LOCALMSPID=OrdererMSP" \
    "ORDERER_GENERAL_LOCALMSPDIR=${ORDERER_DIR}/msp" \
    "ORDERER_GENERAL_TLS_ENABLED=true" \
    "ORDERER_GENERAL_TLS_PRIVATEKEY=${tls_dir}/server.key" \
    "ORDERER_GENERAL_TLS_CERTIFICATE=${tls_dir}/server.crt" \
    "ORDERER_GENERAL_TLS_ROOTCAS=[${tls_dir}/ca.crt]" \
    "ORDERER_GENERAL_GENESISMETHOD=file" \
    "ORDERER_GENERAL_GENESISFILE=${SYSTEM_GENESIS_DIR}/genesis.block" \
    "ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=${tls_dir}/server.crt" \
    "ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=${tls_dir}/server.key" \
    "ORDERER_GENERAL_CLUSTER_ROOTCAS=[${tls_dir}/ca.crt]" \
    "ORDERER_GENERAL_LOGLEVEL=INFO" \
    "ORDERER_FILELEDGER_LOCATION=${ledger_dir}" \
    "ORDERER_CONSENSUS_WALDIR=${wal_dir}" \
    "ORDERER_CONSENSUS_SNAPDIR=${snap_dir}" \
    "ORDERER_OPERATIONS_LISTENADDRESS=127.0.0.1:17050" \
    "ORDERER_METRICS_PROVIDER=prometheus" \
    -- orderer
  wait_for_port 127.0.0.1 7050 "orderer"
}

peer_port() {
  local idx=$1
  echo $((7051 + idx * 1000))
}

peer_chaincode_port() {
  local idx=$1
  echo $((17051 + idx * 1000))
}

peer_component_name() {
  echo "peer$1"
}

peer_host() {
  local idx=$1
  echo "peer${idx}.org1.nebula.com"
}

start_peer() {
  local idx=$1
  local component
  component=$(peer_component_name "${idx}")
  local host
  host=$(peer_host "${idx}")
  local peer_dir="${PEER_ORG_DIR}/peers/${host}"
  local tls_dir="${peer_dir}/tls"
  local data_dir="${DATA_DIR}/${component}"
  local snapshot_dir="${data_dir}/snapshots"
  mkdir -p "${data_dir}" "${snapshot_dir}"
  local listen_port
  listen_port=$(peer_port "${idx}")
  local chaincode_port
  chaincode_port=$(peer_chaincode_port "${idx}")
  local gossip_bootstrap
  case "${idx}" in
    0) gossip_bootstrap="${FABRIC_RESOLVE_HOST}:8051" ;;
    1|2) gossip_bootstrap="${FABRIC_RESOLVE_HOST}:7051" ;;
  esac
  start_process "${component}" \
    "FABRIC_CFG_PATH=${FABRIC_CFG_PATH}" \
    "CORE_PEER_LOCALMSPID=Org1MSP" \
    "CORE_PEER_MSPCONFIGPATH=${peer_dir}/msp" \
    "CORE_PEER_TLS_ENABLED=true" \
    "CORE_PEER_TLS_CERT_FILE=${tls_dir}/server.crt" \
    "CORE_PEER_TLS_KEY_FILE=${tls_dir}/server.key" \
    "CORE_PEER_TLS_ROOTCERT_FILE=${tls_dir}/ca.crt" \
    "CORE_PEER_ID=${host}" \
    "CORE_PEER_ADDRESS=${FABRIC_RESOLVE_HOST}:${listen_port}" \
    "CORE_PEER_LISTENADDRESS=0.0.0.0:${listen_port}" \
    "CORE_PEER_CHAINCODEADDRESS=${FABRIC_RESOLVE_HOST}:${chaincode_port}" \
    "CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:${chaincode_port}" \
    "CORE_PEER_GOSSIP_EXTERNALENDPOINT=${FABRIC_RESOLVE_HOST}:${listen_port}" \
    "CORE_PEER_GOSSIP_BOOTSTRAP=${gossip_bootstrap}" \
    "CORE_PEER_FILESYSTEMPATH=${data_dir}" \
    "CORE_LEDGER_SNAPSHOTS_ROOTDIR=${snapshot_dir}" \
    "CORE_OPERATIONS_LISTENADDRESS=127.0.0.1:$((37050 + idx))" \
    "FABRIC_LOGGING_SPEC=INFO" \
    -- peer node start
  wait_for_port 127.0.0.1 "${listen_port}" "${host}"
}

run_bootstrap() {
  local ready_marker="${RUNTIME_DIR}/.bootstrap-ready"
  local log_file
  log_file=$(log_file_for bootstrap)
  rm -f "${ready_marker}"
  : > "${log_file}"
  echo "[process-runner] running bootstrap (channel + chaincode). This step can take a couple of minutes the first time."
  echo "[process-runner] bootstrap logs: ${log_file}"
  READY_MARKER="${ready_marker}" \
  CC_SRC_PATH="${CHAINCODE_DIR}/asset-transfer-basic" \
  CC_PACKAGE_PATH="${CHAINCODE_DIR}/gateway_1.0.tar.gz" \
  CC_RUNTIME_LANGUAGE=golang \
  FABRIC_ORGS_PATH="${ORG_DIR}" \
  FABRIC_CHANNEL_ARTIFACTS_PATH="${CHANNEL_ARTIFACTS_DIR}" \
  CHAINCODE_HASH_FILE="${CHAINCODE_DIR}/.gateway_hash" \
  FABRIC_CFG_PATH="${CONFIG_DIR}" \
  FABRIC_RESOLVE_HOST="${FABRIC_RESOLVE_HOST}" \
  BOOTSTRAP_KEEPALIVE=0 \
  "${APP_DIR}/scripts/bootstrap.sh" >>"$(log_file_for bootstrap)" 2>&1
  echo "[process-runner] bootstrap completed"
}

start_gateway() {
  build_gateway_binary
  local envs=()
  while read -r line; do
    envs+=("$line")
  done < <(gateway_env)
  start_process gateway "${envs[@]}" -- "${BUILD_DIR}/api-gateway"
  wait_for_port 127.0.0.1 9000 "api gateway"
}

start_stack() {
  ensure_prereqs
  prepare_ports
  prepare_runtime

  local started=()
  cleanup() {
    for ((idx=${#started[@]}-1; idx>=0; idx--)); do
      stop_component "${started[idx]}" || true
    done
  }
  trap cleanup ERR

  start_orderer
  started+=("orderer")
  for idx in 0 1 2; do
    start_peer "${idx}"
    started+=("$(peer_component_name "${idx}")")
  done
  run_bootstrap
  start_gateway
  started+=("gateway")

  trap - ERR
  echo "[process-runner] process stack started (orderer + 3 peers + API gateway)"
}

stop_stack() {
  stop_component gateway
  for idx in 2 1 0; do
    stop_component "$(peer_component_name "${idx}")"
  done
  stop_component orderer
  rm -f "${RUNTIME_DIR}/.bootstrap-ready"
}

component_status() {
  local name=$1
  if component_running "${name}"; then
    local pid
    pid=$(cat "$(pid_file_for "${name}")")
    printf "%-12s running (pid %s)\n" "${name}" "${pid}"
  else
    printf "%-12s stopped\n" "${name}"
  fi
}

status_stack() {
  component_status orderer
  for idx in 0 1 2; do
    component_status "$(peer_component_name "${idx}")"
  done
  component_status gateway
}

tail_logs() {
  local name=$1
  local log_file
  log_file=$(log_file_for "${name}")
  if [ ! -f "${log_file}" ]; then
    die "no logs for ${name} (${log_file} missing)"
  fi
  tail -n 100 -f "${log_file}"
}

case "${ACTION}" in
  start) start_stack ;;
  stop) stop_stack ;;
  status) status_stack ;;
  logs) component=${1:-}; [ -n "${component}" ] || die "usage: $0 logs <component>"; tail_logs "${component}" ;;
  *)
    cat <<'USAGE'
Usage: manage.sh <command>
Commands:
  start    Launch orderer, peers, bootstrap CLI, and the API gateway as local processes
  stop     Stop all managed processes
  status   Show per-component status
  logs <component>  Tail the log file for a component (orderer, peer0, peer1, peer2, gateway, bootstrap)
USAGE
    exit 1
    ;;
esac
