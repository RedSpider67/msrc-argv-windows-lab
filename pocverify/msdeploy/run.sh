#!/bin/sh
# Builds the two command lines offline. No process is spawned and no network call is made
# beyond the npm install of the two published packages.
set -e
cd "$(dirname "$0")"
npm init -y >/dev/null 2>&1 || true
npm i --silent azure-pipelines-tasks-webdeployment-common@4.281.0 azure-pipelines-task-lib@5.280.3
touch msdeploy.exe
node proof.js 2>/dev/null | grep -v 'vso\[task'
