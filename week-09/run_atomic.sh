#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Week 09 - Wrapper for running ONE Atomic Red Team test with timestamp logging
#
# Usage:
#   ./run_atomic.sh <TechniqueID> <TestNumber> details    # read what the test does (runs nothing)
#   ./run_atomic.sh <TechniqueID> <TestNumber> run        # check prerequisites, then execute the test
#   ./run_atomic.sh <TechniqueID> <TestNumber> cleanup    # undo what the test created
#
# Example:
#   ./run_atomic.sh T1059.004 1 details
#   ./run_atomic.sh T1059.004 1 run
#   ./run_atomic.sh T1059.004 1 cleanup
#
# Expected layout (created in the report, section 4):
#   ~/atomic-lab/invoke-atomicredteam/   (Invoke-AtomicRedTeam module)
#   ~/atomic-lab/atomic-red-team/        (the atomics library)
#
# SAFETY:
#   - Run ONLY in your own lab VM (take a snapshot first).
#   - ALWAYS run "details" first and read the commands. Skip any test that
#     downloads tools from the internet or does something you don't understand.
# ---------------------------------------------------------------------------

set -u

LAB="${ATOMIC_LAB:-$HOME/atomic-lab}"
MODULE="${LAB}/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1"
ATOMICS="${LAB}/atomic-red-team/atomics"
LOG="$(cd "$(dirname "$0")" && pwd)/atomic_run_log.txt"

if [ $# -ne 3 ]; then
    sed -n '2,18p' "$0"
    exit 1
fi

TECH="$1"
NUM="$2"
MODE="$3"

# Input validation (the values are passed into a PowerShell command)
if ! [[ "${TECH}" =~ ^T[0-9]{4}(\.[0-9]{3})?$ ]]; then
    echo "Invalid technique ID: ${TECH} (expected e.g. T1059.004)"; exit 1
fi
if ! [[ "${NUM}" =~ ^[0-9]+$ ]]; then
    echo "Invalid test number: ${NUM} (expected a number)"; exit 1
fi
if [ ! -f "${MODULE}" ] || [ ! -d "${ATOMICS}" ]; then
    echo "Atomic Red Team not found under ${LAB}. Follow report section 4 first."; exit 1
fi

stamp() { date '+%Y-%m-%d %H:%M:%S'; }
runps() { pwsh -NoProfile -Command "Import-Module '${MODULE}' -Force; $1"; }

case "${MODE}" in
    details)
        echo "[$(stamp)] DETAILS ${TECH} test ${NUM}" | tee -a "${LOG}"
        runps "Invoke-AtomicTest ${TECH} -TestNumbers ${NUM} -PathToAtomicsFolder '${ATOMICS}' -ShowDetails"
        ;;
    run)
        echo "[$(stamp)] START ${TECH} test ${NUM}" | tee -a "${LOG}"
        runps "Invoke-AtomicTest ${TECH} -TestNumbers ${NUM} -PathToAtomicsFolder '${ATOMICS}' -CheckPrereqs"
        read -r -p "Prerequisites OK and you read the details? Type YES to execute: " ANSWER
        if [ "${ANSWER}" != "YES" ]; then
            echo "[$(stamp)] ABORTED ${TECH} test ${NUM}" | tee -a "${LOG}"; exit 0
        fi
        runps "Invoke-AtomicTest ${TECH} -TestNumbers ${NUM} -PathToAtomicsFolder '${ATOMICS}'"
        echo "[$(stamp)] END ${TECH} test ${NUM}" | tee -a "${LOG}"
        echo "Note the START/END times above: use them to find the events in your SIEM."
        ;;
    cleanup)
        echo "[$(stamp)] CLEANUP ${TECH} test ${NUM}" | tee -a "${LOG}"
        runps "Invoke-AtomicTest ${TECH} -TestNumbers ${NUM} -PathToAtomicsFolder '${ATOMICS}' -Cleanup"
        ;;
    *)
        echo "Unknown mode: ${MODE} (use details, run, or cleanup)"; exit 1
        ;;
esac
