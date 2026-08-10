#!/bin/bash
# prewarm_cache.sh — warm the nova _base image cache on every compute node, in parallel, so heavy images
# (Kali ~6GB) aren't pulled COLD mid-campaign — the cause of the 20-min provision timeouts + retry cascade
# + tail bastion saturation. For each node it boots one throwaway VM pinned to that host
# (--availability-zone nova:<host>) with NO network, which forces nova to download+cache the image into
# that node's _base; waits for ACTIVE (= cached); then deletes it. Run when the cluster is idle.
#
#   Usage:  ./prewarm_cache.sh [IMAGE ...]          default: Kali
#   Env:    FLAVOR=m2.large  PAR=16  AZ=nova
#   No-boot native alternative:
#           openstack --os-compute-api-version 2.81 aggregate cache images <aggregate> <image>
set -u
export OS_CLOUD=openstack
IMAGES=("$@"); [ ${#IMAGES[@]} -eq 0 ] && IMAGES=(Kali)
FLAVOR="${FLAVOR:-m2.large}"
AZ="${AZ:-nova}"
PREFIX=warmcache
PAR="${PAR:-16}"

mapfile -t HOSTS < <(openstack hypervisor list -f value -c "Hypervisor Hostname" | sort)
[ -n "${NODES:-}" ] && read -r -a HOSTS <<< "$NODES"   # optional override: restrict warmup to a given host list
echo "$(date -u +%T) prewarm: ${#HOSTS[@]} nodes x [${IMAGES[*]}]  flavor=$FLAVOR az=$AZ par=$PAR"

warm_one() {   # $1=host   (image comes in via $WARM_IMG)
  local host="$1" img="$WARM_IMG" name="${PREFIX}-${WARM_IMG}-${1}" st="" i attempt=0 max="${MAX_ATTEMPTS:-10}"
  while [ "$attempt" -lt "$max" ]; do   # retry a failed/timed-out boot until the image caches (ACTIVE)
    attempt=$((attempt+1))
    openstack server delete "$name" --wait >/dev/null 2>&1   # clear the prior/stale (or last-failed) one before (re)creating
    if ! openstack --os-compute-api-version 2.37 server create --image "$img" --flavor "$FLAVOR" \
          --availability-zone "${AZ}:${host}" --nic none "$name" >/dev/null 2>&1; then
      echo "  [retry] $host $img create-failed (attempt $attempt/$max)"; sleep 15; continue
    fi
    st=""
    for i in $(seq 1 150); do            # up to ~25 min per attempt
      st=$(openstack server show "$name" -f value -c status 2>/dev/null)
      { [ "$st" = ACTIVE ] || [ "$st" = ERROR ]; } && break
      sleep 10
    done
    if [ "$st" = ACTIVE ]; then
      echo "  [ok]   $host  $img  (attempt $attempt/$max)"
      openstack server delete "$name" >/dev/null 2>&1
      return
    fi
    echo "  [retry] $host $img status=${st:-timeout} (attempt $attempt/$max)"
  done
  echo "  [give-up] $host $img after $max attempts"
  openstack server delete "$name" >/dev/null 2>&1
}
export -f warm_one; export PREFIX FLAVOR AZ OS_CLOUD MAX_ATTEMPTS

for img in "${IMAGES[@]}"; do          # one image at a time (bounds Glance load); all nodes in parallel
  echo "== $img =="
  export WARM_IMG="$img"
  printf '%s\n' "${HOSTS[@]}" | xargs -P "$PAR" -I{} bash -c 'warm_one "{}"'
done
echo "$(date -u +%T) prewarm done"
