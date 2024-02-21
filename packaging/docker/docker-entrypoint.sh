#!/bin/sh
set -e

exec /usr/bin/grafana-auth-reverse-proxy "$@"
