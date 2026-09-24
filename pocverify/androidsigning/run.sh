#!/bin/sh
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
LIB="$DIR/node_modules/azure-pipelines-task-lib"
if [ ! -d "$LIB" ]; then
  echo "run: npm install azure-pipelines-task-lib@5.280.3 in $DIR" >&2
  exit 1
fi
echo "### leg 1: tool resolution"
node "$DIR/resolve.js" "$LIB" 2>&1 | grep -v 'task.debug'
echo
echo "### leg 2: argument construction"
node "$DIR/construct.js" "$LIB" 2>&1 | grep -v 'task.debug'
