#!/bin/bash

set -euo pipefail

if [ "$#" != "1" ]; then
   echo "Usage: $0 <project_root>"
   exit 1
fi

PROJECT_ROOT=$1

PYTHON=${HOME}/venv/bin/python
${PYTHON} -m pip install pre-commit
PRECOMMIT=${HOME}/venv/bin/pre-commit

cd "${PROJECT_ROOT}"

${PRECOMMIT} run --all-files
