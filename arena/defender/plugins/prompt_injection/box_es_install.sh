#!/bin/bash
# Stand up Elasticsearch 9.5.0 on the bare defender box (no docker/java): tarball bundles a JDK.
# Plain HTTP, no auth (matches the harness ES the Perry elasticsearch-py client expects).
set -e
ES_VER=9.5.0
ES_DIR=/opt/elasticsearch-${ES_VER}
TARBALL=elasticsearch-${ES_VER}-linux-x86_64.tar.gz
if curl -s -m 8 -o /dev/null -w '%{http_code}' http://localhost:9200 | grep -q 200; then
  echo "ES already up"; exit 0
fi
id esuser >/dev/null 2>&1 || useradd -m esuser
sysctl -w vm.max_map_count=262144
if [ ! -d "$ES_DIR" ]; then
  cd /opt
  echo "downloading $TARBALL ..."
  curl -fsSL -o "$TARBALL" "https://artifacts.elastic.co/downloads/elasticsearch/${TARBALL}"
  tar xzf "$TARBALL"
  rm -f "$TARBALL"
fi
cat > "$ES_DIR/config/elasticsearch.yml" <<YML
cluster.name: defender-box
node.name: defender
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
YML
mkdir -p "$ES_DIR/config/jvm.options.d"
printf -- "-Xms2g\n-Xmx2g\n" > "$ES_DIR/config/jvm.options.d/heap.options"
chown -R esuser:esuser "$ES_DIR"
# start as esuser, daemonized
sudo -u esuser bash -c "ES_TMPDIR=/tmp $ES_DIR/bin/elasticsearch -d -p /tmp/es.pid"
echo "ES starting (pid file /tmp/es.pid)"
