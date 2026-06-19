#!/usr/bin/env bash

# WAUIG Bank - Enterprise Security Discovery Orchestration Framework
# M9 WP2 - Environment Readiness Control Gate
#
# This script validates local prerequisites before installation.
# It does not install, repair, or modify OS-level prerequisites.

# Treat unset variables as errors to avoid accidental undefined behavior.
set -u

# Create an array to store failed check names.
failures=()

# Create a variable to track the temporary venv test directory.
tmp_venv=""

# Resolve python3 once and reuse the result across all Python-related checks.
python_cmd="$(command -v python3 2>/dev/null || true)"

# Define cleanup logic for temporary test artifacts.
cleanup() {
  # If a temporary venv test directory was created and still exists, remove it.
  if [ -n "${tmp_venv}" ] && [ -d "${tmp_venv}" ]; then
    rm -rf "${tmp_venv}"
  fi
}

# Always run cleanup when the script exits.
trap cleanup EXIT

# Print a standardized PASS line for a readiness check.
record_pass() {
  printf "[CHECK] %-32s PASS\n" "$1"
}

# Print a standardized FAIL line and record the failed check.
record_fail() {
  printf "[CHECK] %-32s FAIL\n" "$1"
  failures+=("$1")
}

# Print a controlled script header.
echo "WAUIG Environment Readiness Check"
echo "---------------------------------"

# Check 1: Confirm python3 is available in PATH.
if [ -n "${python_cmd}" ]; then
  record_pass "python3 present"
else
  record_fail "python3 present"
fi

# Check 2: Confirm python3 version is 3.10 or newer.
if [ -n "${python_cmd}" ]; then
  # Run a small Python version check without printing output.
  if "${python_cmd}" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
  then
    record_pass "python version >= 3.10"
  else
    record_fail "python version >= 3.10"
  fi
else
  # If python3 is missing, version validation must also fail.
  record_fail "python version >= 3.10"
fi

# Check 3: Confirm pip is available through python3.
if [ -n "${python_cmd}" ] && "${python_cmd}" -m pip --version >/dev/null 2>&1; then
  record_pass "pip available"
else
  record_fail "pip available"
fi

# Check 4: Confirm python3 can create a temporary virtual environment.
if [ -n "${python_cmd}" ]; then
  # Create a unique temporary directory for the venv test.
  tmp_venv="$(mktemp -d "${TMPDIR:-/tmp}/wauig-readiness-venv.XXXXXX")"

  # Attempt to create a venv inside the temporary directory.
  if "${python_cmd}" -m venv "${tmp_venv}/.venv" >/dev/null 2>&1; then
    record_pass "venv creation"
  else
    record_fail "venv creation"
  fi
else
  # If python3 is missing, venv creation cannot succeed.
  record_fail "venv creation"
fi

# Print a blank line before final result.
echo ""

# If no failures were recorded, print PASS and exit successfully.
if [ "${#failures[@]}" -eq 0 ]; then
  echo "ENVIRONMENT READINESS: PASS"
  echo "Environment prerequisites are available for controlled venv-based installation."
  exit 0
fi

# If one or more failures were recorded, print FAIL summary.
echo "ENVIRONMENT READINESS: FAIL"
echo ""

# Print each failed check.
echo "Failed Checks:"
for failure in "${failures[@]}"; do
  echo "- ${failure}"
done

# Print enterprise control-gate guidance without remediation commands.
echo ""
echo "One or more required prerequisites are not available."
echo "Do not proceed with framework installation until the environment has been remediated through the organization-approved administration and change-control process."
echo "Re-run this readiness check after remediation is complete."

# Exit non-zero to signal readiness failure.
exit 1
