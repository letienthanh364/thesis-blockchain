#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TAR_BIN=${TAR_BIN:-$(command -v gtar || command -v tar || true)}
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD=(shasum -a 256)
else
  echo "sha256sum or shasum must be installed" >&2
  exit 1
fi

resolve_path() {
  for candidate in "$@"; do
    if [ -n "${candidate}" ] && [ -e "${candidate}" ]; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

ORGS_DIR=$(resolve_path "${FABRIC_ORGS_PATH:-}" "/organizations" "${REPO_DIR}/organizations") || {
  echo "unable to locate Fabric organizations (set FABRIC_ORGS_PATH)" >&2
  exit 1
}
CHANNEL_ARTIFACTS_DIR=$(resolve_path "${FABRIC_CHANNEL_ARTIFACTS_PATH:-}" "/channel-artifacts" "${REPO_DIR}/channel-artifacts") || {
  echo "unable to locate channel artifacts (set FABRIC_CHANNEL_ARTIFACTS_PATH)" >&2
  exit 1
}
CHAINCODE_DIR=$(resolve_path "${FABRIC_CHAINCODE_PATH:-}" "/chaincode" "${REPO_DIR}/chaincode") || {
  echo "unable to locate chaincode directory (set FABRIC_CHAINCODE_PATH)" >&2
  exit 1
}

ORDERER_ROOT=${ORDERER_ROOT:-${ORGS_DIR}/ordererOrganizations/nebula.com}
PEER_ROOT=${PEER_ROOT:-${ORGS_DIR}/peerOrganizations/org1.nebula.com}

CHANNEL_NAME=${CHANNEL_NAME:-nebulachannel}
CC_NAME=${CHAINCODE_NAME:-gateway}
CC_VERSION=${CHAINCODE_VERSION:-1.0}
CC_SEQUENCE=${CHAINCODE_SEQUENCE:-1}
CC_SRC_PATH=${CHAINCODE_SRC_PATH:-${CHAINCODE_DIR}/asset-transfer-basic}
CC_RUNTIME_LANGUAGE=${CHAINCODE_RUNTIME_LANGUAGE:-golang}
CC_LABEL="${CC_NAME}_${CC_VERSION}"
CC_PACKAGE_PATH=${CC_PACKAGE_PATH:-${CHAINCODE_DIR}/${CC_LABEL}.tar.gz}
# When set, network connections use this host instead of FQDNs.
FABRIC_RESOLVE_HOST="${FABRIC_RESOLVE_HOST:-}"

resolve_peer_addr() {
  local idx=$1
  local port=$((7051 + idx * 1000))
  if [ -n "${FABRIC_RESOLVE_HOST}" ]; then
    echo "${FABRIC_RESOLVE_HOST}:${port}"
  else
    echo "peer${idx}.org1.nebula.com:${port}"
  fi
}

resolve_orderer_addr() {
  if [ -n "${FABRIC_RESOLVE_HOST}" ]; then
    echo "${FABRIC_RESOLVE_HOST}:7050"
  else
    echo "orderer.nebula.com:7050"
  fi
}

ORDERER_CA=${ORDERER_CA:-${ORDERER_ROOT}/orderers/orderer.nebula.com/msp/tlscacerts/tlsca.nebula.com-cert.pem}
ORDERER_TLS_HOSTNAME_OVERRIDE=${ORDERER_TLS_HOSTNAME_OVERRIDE:-orderer.nebula.com}
GENESIS_CHANNEL_TX=${GENESIS_CHANNEL_TX:-${CHANNEL_ARTIFACTS_DIR}/nebula-channel.tx}
CHANNEL_BLOCK=${CHANNEL_BLOCK:-${CHANNEL_ARTIFACTS_DIR}/${CHANNEL_NAME}.block}
READY_MARKER=${READY_MARKER:-${SCRIPT_DIR}/.bootstrap-ready}
CC_HASH_FILE=${CHAINCODE_HASH_FILE:-${CHAINCODE_DIR}/.${CC_NAME}_hash}
FORCE_CHAINCODE_REDEPLOY=${CHAINCODE_FORCE_REDEPLOY:-0}
CHAINCODE_HASH=""
COMMITTED_SEQUENCE=0
# Space-delimited list of peer indices to use as commit endorsers (defaults to peer0 only).
COMMIT_PEER_INDICES=${CHAINCODE_COMMIT_PEER_INDICES:-"0"}
PEER_CONN_PARMS=()

log() {
  echo "[bootstrap] $1"
}

calculateChaincodeHash() {
  if [ ! -d "${CC_SRC_PATH}" ]; then
    echo ""
    return
  fi
  if [ -n "${TAR_BIN}" ]; then
    "${TAR_BIN}" -cf - -C "${CC_SRC_PATH}" . | "${SHA_CMD[@]}" | awk '{print $1}'
  else
    tar -cf - -C "${CC_SRC_PATH}" . | "${SHA_CMD[@]}" | awk '{print $1}'
  fi
}

recordChaincodeHash() {
  if [ -z "${CHAINCODE_HASH}" ]; then
    return
  fi
  echo "${CHAINCODE_HASH}" > "${CC_HASH_FILE}"
}

detectCommittedSequence() {
  setGlobals 0
  if peer lifecycle chaincode querycommitted --channelID ${CHANNEL_NAME} --name ${CC_NAME} > /tmp/committed_${CC_NAME}.txt 2>/tmp/committed_${CC_NAME}.err; then
    local seq
    seq=$(awk '
      /Sequence:/ {
        for (i = 1; i <= NF; i++) {
          if ($i == "Sequence:") {
            next_field = $(i+1)
            gsub(",", "", next_field)
            print next_field
            exit
          }
        }
      }' /tmp/committed_${CC_NAME}.txt)
    if [ -n "${seq}" ]; then
      COMMITTED_SEQUENCE=${seq}
    else
      COMMITTED_SEQUENCE=0
    fi
  else
    COMMITTED_SEQUENCE=0
  fi
}

detectChaincodeChange() {
  CHAINCODE_HASH=$(calculateChaincodeHash)
  if [ "${FORCE_CHAINCODE_REDEPLOY}" = "1" ]; then
    return
  fi
  if [ -z "${CHAINCODE_HASH}" ]; then
    return
  fi
  if [ -f "${CC_HASH_FILE}" ]; then
    local recorded
    recorded=$(cat "${CC_HASH_FILE}")
    if [ "${recorded}" = "${CHAINCODE_HASH}" ]; then
      return
    fi
  fi
  FORCE_CHAINCODE_REDEPLOY=1
  log "chaincode source change detected; redeployment will be forced"
}

prepareChaincodeDeployment() {
  detectCommittedSequence
  detectChaincodeChange
  if [ "${FORCE_CHAINCODE_REDEPLOY}" = "1" ] && [ "${COMMITTED_SEQUENCE}" -gt 0 ] && [ "${CC_SEQUENCE}" -le "${COMMITTED_SEQUENCE}" ]; then
    local previous=${CC_SEQUENCE}
    CC_SEQUENCE=$((COMMITTED_SEQUENCE + 1))
    log "auto-incrementing chaincode sequence from ${previous} to ${CC_SEQUENCE}"
  fi
}

setGlobals() {
  local PEER_INDEX=$1
  local PEER_ADDRESS
  PEER_ADDRESS=$(resolve_peer_addr "${PEER_INDEX}")
  export CORE_PEER_LOCALMSPID=Org1MSP
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_MSPCONFIGPATH=${PEER_ROOT}/users/Admin@org1.nebula.com/msp
  export CORE_PEER_TLS_ROOTCERT_FILE=${PEER_ROOT}/peers/peer${PEER_INDEX}.org1.nebula.com/tls/ca.crt
  export CORE_PEER_ADDRESS=${PEER_ADDRESS}
  # Override TLS hostname so cert validation passes when connecting via localhost.
  export CORE_PEER_TLS_SERVERHOSTOVERRIDE="peer${PEER_INDEX}.org1.nebula.com"
}

buildPeerConnectionParameters() {
  PEER_CONN_PARMS=()
  for idx in ${COMMIT_PEER_INDICES}; do
    local address
    address=$(resolve_peer_addr "${idx}")
    local tls_root="${PEER_ROOT}/peers/peer${idx}.org1.nebula.com/tls/ca.crt"
    PEER_CONN_PARMS+=("--peerAddresses" "${address}" "--tlsRootCertFiles" "${tls_root}")
  done
  if [ "${#PEER_CONN_PARMS[@]}" -eq 0 ]; then
    local default_addr
    default_addr=$(resolve_peer_addr 0)
    PEER_CONN_PARMS=(--peerAddresses "${default_addr}" --tlsRootCertFiles ${PEER_ROOT}/peers/peer0.org1.nebula.com/tls/ca.crt)
  fi
}

waitForPeer() {
  local ADDRESS=$1
  local HOST=${ADDRESS%:*}
  local PORT=${ADDRESS##*:}
  for i in {1..20}; do
    if (echo >/dev/tcp/${HOST}/${PORT}) >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "failed to reach ${ADDRESS}" >&2
  exit 1
}

createChannel() {
  setGlobals 0
  if peer channel getinfo -c ${CHANNEL_NAME} >/dev/null 2>&1; then
    log "channel ${CHANNEL_NAME} already exists"
    return
  fi

  log "creating channel ${CHANNEL_NAME}"
  local max_retries=5
  for attempt in $(seq 1 ${max_retries}); do
    if peer channel create \
      -o "$(resolve_orderer_addr)" \
      --ordererTLSHostnameOverride "${ORDERER_TLS_HOSTNAME_OVERRIDE}" \
      -c ${CHANNEL_NAME} \
      -f ${GENESIS_CHANNEL_TX} \
      --outputBlock ${CHANNEL_BLOCK} \
      --tls --cafile ${ORDERER_CA} 2>&1; then
      return
    fi
    log "channel create attempt ${attempt}/${max_retries} failed, retrying in 5s..."
    sleep 5
  done
  log "failed to create channel after ${max_retries} attempts"
  exit 1
}

joinChannel() {
  if [ ! -f ${CHANNEL_BLOCK} ]; then
    log "fetching channel block"
    setGlobals 0
    peer channel fetch 0 ${CHANNEL_BLOCK} -o "$(resolve_orderer_addr)" --ordererTLSHostnameOverride "${ORDERER_TLS_HOSTNAME_OVERRIDE}" -c ${CHANNEL_NAME} --tls --cafile ${ORDERER_CA}
  fi

  for idx in 0 1 2; do
    setGlobals ${idx}
    if peer channel list >/tmp/channels_${idx}.txt 2>/tmp/channels_${idx}.err && grep -q ${CHANNEL_NAME} /tmp/channels_${idx}.txt; then
      log "peer${idx} already in channel"
      continue
    fi
    log "peer${idx} joining channel"
    peer channel join -b ${CHANNEL_BLOCK}
  done
}

packageChaincode() {
  setGlobals 0
  if [ "${FORCE_CHAINCODE_REDEPLOY}" != "1" ] && [ -f ${CC_PACKAGE_PATH} ]; then
    return
  fi
  log "packaging chaincode (${CC_LABEL})"
  rm -f ${CC_PACKAGE_PATH}
  peer lifecycle chaincode package ${CC_PACKAGE_PATH} \
    --path ${CC_SRC_PATH} \
    --lang ${CC_RUNTIME_LANGUAGE} \
    --label ${CC_LABEL}
}

installChaincode() {
  for idx in 0 1 2; do
    setGlobals ${idx}
    if [ "${FORCE_CHAINCODE_REDEPLOY}" != "1" ] && peer lifecycle chaincode queryinstalled | grep -q ${CC_LABEL}; then
      log "chaincode already installed on peer${idx}"
      continue
    fi
    if [ "${FORCE_CHAINCODE_REDEPLOY}" = "1" ]; then
      log "reinstalling chaincode on peer${idx}"
    else
      log "installing chaincode on peer${idx}"
    fi
    if ! output=$(peer lifecycle chaincode install ${CC_PACKAGE_PATH} 2>&1); then
      if echo "${output}" | grep -qi "already successfully installed"; then
        log "chaincode already installed on peer${idx} (detected during install)"
        continue
      fi
      echo "${output}" >&2
      exit 1
    fi
  done
}

getPackageID() {
  setGlobals 0
  peer lifecycle chaincode queryinstalled > /tmp/installed_chaincodes.txt
  PACKAGE_ID=$(grep ${CC_LABEL} /tmp/installed_chaincodes.txt | tail -n 1 | awk -F ',' '{print $1}' | awk '{print $3}')
  export PACKAGE_ID
}

approveChaincode() {
  setGlobals 0
  if [ "${FORCE_CHAINCODE_REDEPLOY}" != "1" ] && [ "${COMMITTED_SEQUENCE}" -ge "${CC_SEQUENCE}" ]; then
    log "chaincode already approved"
    return
  fi

  if [ "${FORCE_CHAINCODE_REDEPLOY}" != "1" ] && peer lifecycle chaincode checkcommitreadiness --channelID ${CHANNEL_NAME} --name ${CC_NAME} --version ${CC_VERSION} --sequence ${CC_SEQUENCE} --output json | grep -q '"Org1MSP": true'; then
    log "chaincode already approved"
    return
  fi

  log "approving chaincode"
  peer lifecycle chaincode approveformyorg \
    -o "$(resolve_orderer_addr)" \
    --ordererTLSHostnameOverride "${ORDERER_TLS_HOSTNAME_OVERRIDE}" \
    --channelID ${CHANNEL_NAME} \
    --name ${CC_NAME} \
    --version ${CC_VERSION} \
    --package-id ${PACKAGE_ID} \
    --sequence ${CC_SEQUENCE} \
    --tls --cafile ${ORDERER_CA}
}

commitChaincode() {
  if [ "${FORCE_CHAINCODE_REDEPLOY}" != "1" ] && peer lifecycle chaincode querycommitted --channelID ${CHANNEL_NAME} --name ${CC_NAME} | grep -q "Sequence: ${CC_SEQUENCE}"; then
    log "chaincode already committed"
    return
  fi
  log "committing chaincode"
  buildPeerConnectionParameters
  peer lifecycle chaincode commit \
    -o "$(resolve_orderer_addr)" \
    --ordererTLSHostnameOverride "${ORDERER_TLS_HOSTNAME_OVERRIDE}" \
    --channelID ${CHANNEL_NAME} \
    --name ${CC_NAME} \
    --version ${CC_VERSION} \
    --sequence ${CC_SEQUENCE} \
    --tls --cafile ${ORDERER_CA} \
    "${PEER_CONN_PARMS[@]}"
  recordChaincodeHash
}

initializeLedger() {
  setGlobals 0
  log "invoking InitLedger"
  peer chaincode invoke \
    -o "$(resolve_orderer_addr)" \
    --ordererTLSHostnameOverride "${ORDERER_TLS_HOSTNAME_OVERRIDE}" \
    -C ${CHANNEL_NAME} \
    -n ${CC_NAME} \
    --tls --cafile ${ORDERER_CA} \
    --peerAddresses "$(resolve_peer_addr 0)" --tlsRootCertFiles ${PEER_ROOT}/peers/peer0.org1.nebula.com/tls/ca.crt \
    -c '{"function":"InitLedger","Args":[]}' || true
}

main() {
  waitForPeer "$(resolve_peer_addr 0)" || true
  waitForPeer "$(resolve_peer_addr 1)" || true
  waitForPeer "$(resolve_peer_addr 2)" || true
  waitForPeer "$(resolve_orderer_addr)" || true
  createChannel
  joinChannel
  prepareChaincodeDeployment
  packageChaincode
  installChaincode
  getPackageID
  approveChaincode
  commitChaincode
  initializeLedger
  log "network bootstrap completed"
  touch ${READY_MARKER}
  if [ "${BOOTSTRAP_KEEPALIVE:-1}" = "1" ]; then
    tail -f /dev/null
  fi
}

main
