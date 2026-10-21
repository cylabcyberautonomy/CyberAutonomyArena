#!/bin/bash
# prewarm_cache.sh — warm the nova _base image cache on every compute node so heavy images
# (kali_base ~7.5GB) aren't pulled COLD mid-campaign — the cause of the 20-min provision timeouts +
# retry cascade + tail bastion saturation. For each node it boots one throwaway VM pinned to that host
# (--availability-zone nova:<host>) with NO network, which forces nova to download+cache the image into
# that node's _base; waits for ACTIVE (= cached); then deletes it. Run when the cluster is idle.
#
#   Usage:  ./prewarm_cache.sh [IMAGE ...]          default: kali_base
#   Env:    FLAVOR=m2.large  PAR=6  STAGGER=20  RETRY_BACKOFF=30  MAX_ATTEMPTS=10  AZ=nova  NODES="h1 h2"
#   No-boot native alternative (needs a host aggregate, which this cloud does not have):
#           openstack --os-compute-api-version 2.81 aggregate cache images <aggregate> <image>
#
# Glance throughput is the binding constraint, NOT nova. Firing all 16 nodes at one 7.5GB image makes
# Glance refuse connections outright — the node reports
#   "Connection broken: IncompleteRead(0 bytes read, 7530676224 more expected)"
# and the VM lands in ERROR within seconds. So creates are SERIALIZED and SPACED:
#   PAR     — how many nodes may be in-flight (downloading/booting) at once
#   STAGGER — seconds held between consecutive `server create` calls, so pulls ramp in rather than burst
#   RETRY_BACKOFF — per-attempt backoff (attempt N waits N*RETRY_BACKOFF) instead of retrying instantly,
#                   which previously re-hammered a Glance that was already saturated
set -u
export OS_CLOUD=openstack
IMAGES=("$@"); [ ${#IMAGES[@]} -eq 0 ] && IMAGES=(kali_base)
FLAVOR="${FLAVOR:-m2.large}"
AZ="${AZ:-nova}"
PREFIX=warmcache
PAR="${PAR:-6}"
STAGGER="${STAGGER:-20}"
RETRY_BACKOFF="${RETRY_BACKOFF:-30}"
LOCKFILE="/tmp/$(id -un)/prewarm-create.lock"
mkdir -p "$(dirname "$LOCKFILE")"

mapfile -t HOSTS < <(openstack hypervisor list -f value -c "Hypervisor Hostname" | sort)
[ -n "${NODES:-}" ] && read -r -a HOSTS <<< "$NODES"   # optional override: restrict warmup to a given host list
echo "$(date -u +%T) prewarm: ${#HOSTS[@]} nodes x [${IMAGES[*]}]  flavor=$FLAVOR az=$AZ par=$PAR stagger=${STAGGER}s"

warm_one() {   # $1=host   (image comes in via $WARM_IMG)
  local host="$1" img="$WARM_IMG" name="${PREFIX}-${WARM_IMG}-${1}" st="" i attempt=0 missing=0 backoff
  local max="${MAX_ATTEMPTS:-10}"
  while [ "$attempt" -lt "$max" ]; do   # retry a failed/timed-out boot until the image caches (ACTIVE)
    attempt=$((attempt+1))
    openstack server delete "$name" --wait >/dev/null 2>&1   # clear the prior/stale (or last-failed) one before (re)creating
    # Hold the lock across create + STAGGER so only one pull starts per STAGGER seconds, cluster-wide.
    (
      flock 9
      openstack --os-compute-api-version 2.37 server create --image "$img" --flavor "$FLAVOR" \
        --availability-zone "${AZ}:${host}" --nic none "$name" >/dev/null 2>&1
      rc=$?
      sleep "$STAGGER"
      exit $rc
    ) 9>"$LOCKFILE"
    if [ $? -ne 0 ]; then
      echo "  [retry] $host $img create-failed (attempt $attempt/$max)"; sleep 15; continue
    fi
    st=""; missing=0
    for i in $(seq 1 150); do            # up to ~25 min per attempt
      st=$(openstack server show "$name" -f value -c status 2>/dev/null)
      if [ -z "$st" ]; then
        # The VM vanished (deleted out-of-band — e.g. an arena clean-slate wipes the whole cloud on
        # BOTH startup and shutdown). Bail out fast instead of polling a dead name for 25 minutes.
        missing=$((missing+1))
        [ "$missing" -ge 3 ] && { st=gone; break; }
      else
        missing=0
        { [ "$st" = ACTIVE ] || [ "$st" = ERROR ]; } && break
      fi
      sleep 10
    done
    if [ "$st" = ACTIVE ]; then
      echo "  [ok]   $host  $img  (attempt $attempt/$max)"
      openstack server delete "$name" >/dev/null 2>&1
      return
    fi
    backoff=$(( attempt * RETRY_BACKOFF ))
    echo "  [retry] $host $img status=${st:-timeout} (attempt $attempt/$max; backoff ${backoff}s)"
    sleep "$backoff"
  done
  echo "  [give-up] $host $img after $max attempts"
  openstack server delete "$name" >/dev/null 2>&1
}
export -f warm_one; export PREFIX FLAVOR AZ OS_CLOUD MAX_ATTEMPTS STAGGER RETRY_BACKOFF LOCKFILE

for img in "${IMAGES[@]}"; do          # one image at a time (bounds Glance load); nodes ramp in via PAR+STAGGER
  echo "== $img =="
  export WARM_IMG="$img"
  printf '%s\n' "${HOSTS[@]}" | xargs -P "$PAR" -I{} bash -c 'warm_one "{}"'
done
echo "$(date -u +%T) prewarm done"
