#!/usr/bin/env bash
set -euo pipefail
kind delete cluster --name vuln-lab || true
