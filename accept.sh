#!/bin/sh
Z62_ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$Z62_ROOT/z62" accept "$@"
