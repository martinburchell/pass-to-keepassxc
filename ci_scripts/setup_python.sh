#!/bin/bash

set -euo pipefail

if [ "$#" != "1" ]; then
   echo "Usage: $0 <project_root>"
   exit 1
fi

PROJECT_ROOT=$1

python -m venv "${HOME}/venv"
PYTHON=${HOME}/venv/bin/python
${PYTHON} -VV
${PYTHON} -m site
${PYTHON} -m ensurepip --upgrade
${PYTHON} -m pip install -U pip setuptools

cd "${PROJECT_ROOT}"
