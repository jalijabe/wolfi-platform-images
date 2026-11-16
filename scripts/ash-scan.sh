#!/usr/bin/env bash
# Run ASH and fail closed if it did not actually scan (see imagefactory/ashcheck.py).
# Usage: scripts/ash-scan.sh <container|local|precommit> <ash-version>
#
# A scan that did not run (e.g. ASH's image build hit a registry rate limit, as
# seen on shared CI runners) is retried a bounded number of times. A scan that
# ran and found something is never retried: its exit code is returned as is.
set -euo pipefail
mode=${1:?usage: $0 <mode> <ash-version>}
version=${2:?usage: $0 <mode> <ash-version>}
attempts=${ASH_ATTEMPTS:-3}
backoff=${ASH_RETRY_SECONDS:-60}
cd "$(dirname "$0")/.."

# cdk-nag is disabled in .ash/.ash.yaml (no CloudFormation or CDK here; see the reason there).
allow=(--allow-missing cdk-nag)
if [[ $mode != container ]]; then
  allow=(--allow-missing cdk-nag,cfn-nag)   # cfn-nag needs container mode
fi

for ((i = 1; i <= attempts; i++)); do
  rm -rf .ash/ash_output   # never let a previous run's reports stand in for this one
  rc=0
  uvx --python 3.12 "git+https://github.com/awslabs/automated-security-helper.git@${version}" \
    --mode "$mode" --config .ash/.ash.yaml || rc=$?
  if uv run --frozen python -m imagefactory.ashcheck .ash/ash_output "${allow[@]}"; then
    exit "$rc"   # 0 clean, 2 actionable findings, 1 ASH error
  fi
  if ((i < attempts)); then
    echo "ASH did not complete a scan (attempt $i of $attempts, exit $rc); retrying in ${backoff}s." >&2
    sleep "$backoff"
  fi
done
echo "ASH did not complete a scan after $attempts attempts; failing closed." >&2
exit 3
