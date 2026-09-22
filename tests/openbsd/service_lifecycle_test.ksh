#!/bin/ksh

set -eu
umask 077

readonly service="gateholdd"
readonly api_user="_gateholdapi"
readonly daemon_path="/usr/local/sbin/gateholdd"
readonly client_path="/usr/local/bin/gateholdctl"
readonly service_path="/etc/rc.d/gateholdd"
readonly journal_root="/var/log/gatehold"
readonly journal_path="${journal_root}/operations.jsonl"
readonly revision_root="/var/db/gatehold/revisions"
readonly transaction_root="/var/db/gatehold/transactions"
readonly pending_path="${transaction_root}/pending-activation"
readonly socket_path="/var/run/gatehold/controller.sock"

cleanup_required=no

log_step() {
	print -r -- "GH-LAB-0001: $1"
}

fail() {
	print -ru2 -- "GH-LAB-1001: $1"
	exit 1
}

cleanup() {
	if [ "${cleanup_required}" = yes ]; then
		print -ru2 -- \
		    "GH-LAB-1002: Stopping the daemon started by the failed test."
		rcctl stop "${service}" >/dev/null 2>&1 || true
	fi
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if [ "$#" -ne 1 ] || [ "$1" != "--confirm-disposable-lab" ]; then
	print -ru2 -- \
	    "Usage: $0 --confirm-disposable-lab"
	fail "Explicit disposable-lab confirmation is required."
fi

[ "$(uname -s)" = OpenBSD ] || fail "This test runs only on OpenBSD."
[ "$(id -u)" = 0 ] || fail "This lifecycle test must run as root."

for command in rcctl stat id uname awk date sleep; do
	command -v "${command}" >/dev/null 2>&1 || \
	    fail "A required OpenBSD base command is unavailable."
done

[ -x "${daemon_path}" ] || fail "The installed daemon is unavailable."
[ -x "${client_path}" ] || fail "The installed client is unavailable."
[ -x "${service_path}" ] || fail "The installed rc.d service is unavailable."

daemon_metadata="$(stat -f '%Su:%Sg:%OLp' "${daemon_path}")"
client_metadata="$(stat -f '%Su:%Sg:%OLp' "${client_path}")"
service_metadata="$(stat -f '%Su:%Sg:%OLp' "${service_path}")"
[ "${daemon_metadata}" = "root:bin:555" ] || \
	fail "The daemon owner, group, or mode differs from the package contract."
[ "${client_metadata}" = "root:bin:555" ] || \
	fail "The client owner, group, or mode differs from the package contract."
[ "${service_metadata}" = "root:wheel:555" ] || \
	fail "The rc.d owner, group, or mode differs from the package contract."

api_uid="$(id -u "${api_user}")" || fail "The API account is unavailable."
api_gid="$(id -g "${api_user}")" || fail "The API group is unavailable."
case "${api_uid}" in
	''|*[!0-9]*) fail "The API user identity is not numeric." ;;
esac
case "${api_gid}" in
	''|*[!0-9]*) fail "The API group identity is not numeric." ;;
esac

readonly expected_flags="--journal-root ${journal_root} --revision-root ${revision_root} --transaction-root ${transaction_root} --socket-path ${socket_path} --allowed-uid ${api_uid} --allowed-gid ${api_gid}"
configured_flags="$(rcctl get "${service}" flags)" || \
	fail "The service flags could not be read."
[ "${configured_flags}" = "${expected_flags}" ] || \
	fail "The service flags do not match the isolated-lab contract."
[ "$(rcctl get "${service}" user)" = root ] || \
	fail "The privileged controller is not configured to run as root."
[ "$(rcctl get "${service}" logger)" = daemon.info ] || \
	fail "The service logger does not match the package contract."
rcctl get "${service}" status >/dev/null || \
	fail "The service is not enabled for boot lifecycle verification."

if rcctl check "${service}" >/dev/null 2>&1; then
	fail "The test refuses to take ownership of a running service."
fi
[ ! -e "${socket_path}" ] || \
	fail "The controller socket path must be absent before the test."
[ ! -e "${pending_path}" ] || \
	fail "A pending activation could make startup recovery mutate PF."

if [ -e "${journal_path}" ]; then
	[ -f "${journal_path}" ] && [ ! -L "${journal_path}" ] || \
	    fail "The operation journal is not a regular non-symlink file."
	[ "$(stat -f '%Su:%OLp' "${journal_path}")" = "root:600" ] || \
	    fail "The operation journal does not satisfy its private-file contract."
	journal_before="$(stat -f '%d:%i:%z' "${journal_path}")"
else
	journal_before=absent
fi

log_step "Checking the installed daemon configuration without side effects."
rcctl configtest "${service}" >/dev/null
if [ -e "${journal_path}" ]; then
	journal_after="$(stat -f '%d:%i:%z' "${journal_path}")"
else
	journal_after=absent
fi
[ "${journal_after}" = "${journal_before}" ] || \
	fail "Configuration checking changed the durable journal."
[ ! -e "${socket_path}" ] || \
	fail "Configuration checking created the controller socket."

event_count() {
	if [ ! -f "${journal_path}" ]; then
		print 0
		return
	fi
	awk -v event_id="$1" \
	    'index($0, "\"event_id\":\"" event_id "\"") { count++ } END { print count + 0 }' \
	    "${journal_path}"
}

daemon_start_before="$(event_count GH-DMN-0001)"
service_ready_before="$(event_count GH-SVC-0002)"
signal_before="$(event_count GH-SIG-0002)"
daemon_stop_before="$(event_count GH-DMN-0002)"

wait_for_socket() {
	attempt=0
	while [ "${attempt}" -lt 20 ]; do
		[ -S "${socket_path}" ] && return 0
		sleep 1
		attempt=$((attempt + 1))
	done
	return 1
}

assert_running_contract() {
	rcctl check "${service}" >/dev/null || \
	    fail "rc.d does not report the daemon as running."
	wait_for_socket || fail "The controller socket did not become ready."
	[ "$(stat -f '%Su:%Sg:%OLp' "${socket_path}")" = \
	    "root:${api_user}:660" ] || \
	    fail "The controller socket owner, API group, or mode is incorrect."
}

log_step "Starting the foreground daemon through rc.d."
cleanup_required=yes
rcctl start "${service}" >/dev/null
assert_running_contract

log_step "Restarting the daemon through the native supervisor."
rcctl restart "${service}" >/dev/null
assert_running_contract

timeout="$(rcctl get "${service}" timeout)" || \
	fail "The service timeout could not be read."
case "${timeout}" in
	''|*[!0-9]*) fail "The service timeout is not numeric." ;;
esac

log_step "Stopping the daemon cooperatively through SIGTERM."
stop_started="$(date +%s)"
rcctl stop "${service}" >/dev/null
cleanup_required=no
stop_finished="$(date +%s)"
stop_elapsed=$((stop_finished - stop_started))
[ "${stop_elapsed}" -le $((timeout + 2)) ] || \
	fail "Cooperative shutdown exceeded the configured rc.d timeout."
if rcctl check "${service}" >/dev/null 2>&1; then
	fail "rc.d still reports the daemon as running after stop."
fi
[ ! -e "${socket_path}" ] || \
	fail "Cooperative shutdown did not remove the owned socket path."

daemon_start_after="$(event_count GH-DMN-0001)"
service_ready_after="$(event_count GH-SVC-0002)"
signal_after="$(event_count GH-SIG-0002)"
daemon_stop_after="$(event_count GH-DMN-0002)"

[ $((daemon_start_after - daemon_start_before)) -eq 2 ] || \
	fail "The journal does not contain exactly two daemon starts."
[ $((service_ready_after - service_ready_before)) -eq 2 ] || \
	fail "The journal does not contain exactly two readiness events."
[ $((signal_after - signal_before)) -eq 2 ] || \
	fail "The journal does not contain exactly two cooperative stop signals."
[ $((daemon_stop_after - daemon_stop_before)) -eq 2 ] || \
	fail "The journal does not contain exactly two clean daemon stops."

log_step "PASS: configtest, start, restart, stop, socket delegation, and audit lifecycle are verified."
