#!/bin/bash

OUTPUT_DIR=${OUTPUT_DIR:-benchmarks}
FILE_100KB=${FILE_100KB:-file_100kB.bin}
FILE_1MB=${FILE_1MB:-file_1MB.bin}
FILE_100MB=${FILE_100MB:-file_100MB.bin}
FILE_100MB=${FILE_100MB:-file_100MB.bin}
FILE_500MB=${FILE_500MB:-file_500MB.bin}
SERVER_PORT=${SERVER_PORT:-5557}
SERVER_BIN=${SERVER_BIN:-./server}
CLIENT_BIN=${CLIENT_BIN:-./client}
BENCH_COUNT=${BENCH_COUNT:-5000}
BENCH_TIME=${BENCH_TIME:-2}

TLS_OVERHEAD=$((5 + 8 + 16))
DTLS_OVERHEAD=$((13 + 8 + 16))

CLIENT_EXEC="${CLIENT_BIN} --server-port ${SERVER_PORT} --server-host localhost --json --drop-caches"

function xecho {
	echo ">>> $@"
}

function run_server {
	${SERVER_BIN} --port ${SERVER_PORT} "$@" &
}

function stop_server {
	kill -9 %%
}

function run_client {
	sleep 2 # give server some time to spawn
	eval ${CLIENT_EXEC} $@
}

[ `id -u` -eq 0 ] || {
	echo "This script has to be run under root due to cache drops" >&2
	exit 1
}

[ -d "${OUTPUT_DIR}" ] && {
	xecho "Removing old output file '${OUTPUT_DIR}'"
	rm -rf "${OUTPUT_DIR}"
}

mkdir -p "${OUTPUT_DIR}"

xecho "Preparing files"
[ -f "${FILE_100KB}" ] || dd if=/dev/urandom of="${FILE_100KB}" bs=1000 count=100
[ -f "${FILE_1MB}" ]   || dd if=/dev/urandom of="${FILE_1MB}" bs=1000 count=1000
[ -f "${FILE_100MB}" ] || dd if=/dev/urandom of="${FILE_100MB}" bs=1000 count=100000
[ -f "${FILE_500MB}" ] || dd if=/dev/urandom of="${FILE_500MB}" bs=1000 count=500000

# we need to do comparison tests separately for Gnu TLS and AF_KTLS now because
# Gnu TLS does not handle getting recv sequence number in DTLS, see xlibgnutls.c
#
# for details of how tests are implemented, see action.c
#
# TLS note: if running test where client does not collect data from server,
# server has to be run with --no-echo, to avoid kernel recv stack to be
# fulfilled
for protocol in "--tls" "--dtls"; do
	for i in `seq 1 3`; do
		for payload in 1000 1280 1400 4000 6000 9000 13000 16000; do
			# AF_KTLS is using MTU for raw data, without TLS/DTLS packetization
			# overhead
			if [ "${protocol}" == "--tls" ]; then
				SENDFILE_MTU=$(( ${payload} + ${TLS_OVERHEAD} ))
			else
				SENDFILE_MTU=$(( ${payload} + ${DTLS_OVERHEAD} ))
			fi

			########## sendfile(2) vs userspace buffered copy
			for file in "${FILE_100KB}" "${FILE_1MB}" "${FILE_100MB}" "${FILE_500MB}"; do
				TEST_OUTPUT_DIR="${OUTPUT_DIR}/sendfile-${file}-${payload}${protocol}"
				xecho "Performing benchmark, output: ${TEST_OUTPUT_DIR}"
				[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"

				run_server "${protocol}" --no-echo
				run_client "${protocol}" --sendfile "${file}" --sendfile-mtu ${SENDFILE_MTU} \
					--sendfile-user ${file} --payload ${payload} \
					--output "${TEST_OUTPUT_DIR}/output.${i}.json"
				stop_server
			done

			########## sendmsg(2) and recvmsg(2) - COUNT
			TEST_OUTPUT_DIR="${OUTPUT_DIR}/transmission-count-${BENCH_COUNT}-${payload}${protocol}"
			xecho "Performing benchmark, output ${TEST_OUTPUT_DIR}"
			[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"

			run_server "${protocol}"
			run_client "${protocol}" --send-ktls-count "${BENCH_COUNT}" --payload ${payload} \
				--output "${TEST_OUTPUT_DIR}/ktls-output.${i}.json"
			stop_server
			run_server "${protocol}"
			run_client "${protocol}" --send-gnutls-count "${BENCH_COUNT}" --payload ${payload} \
				--output "${TEST_OUTPUT_DIR}/gnutls-output.${i}.json"
			stop_server

			########## splice(2) - COUNT
			TEST_OUTPUT_DIR="${OUTPUT_DIR}/splice-count-dev-zero-${payload}${protocol}"
			xecho "Performing benchmark, output: ${TEST_OUTPUT_DIR}"
			[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"
			run_server "${protocol}" --no-echo
			run_client "${protocol}" --splice-count "${BENCH_COUNT}" --payload ${payload} \
				--splice-file /dev/zero --output "${TEST_OUTPUT_DIR}/output.${i}.json"
			stop_server

			########### splice(2) echo -- "ping-pong" - COUNT
			TEST_OUTPUT_DIR="${OUTPUT_DIR}/splice-echo-count-${payload}${protocol}"
			xecho "Performing benchmark, output: ${TEST_OUTPUT_DIR}"
			[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"
			run_server "${protocol}" --mtu ${payload}
			run_client "${protocol}" --splice-echo-count "${BENCH_COUNT}" --payload ${payload} \
				--sendfile-mtu ${SENDFILE_MTU} --output "${TEST_OUTPUT_DIR}/output.${i}.json"
			stop_server

			########## sendmsg(2) and recvmsg(2) - TIME
			TEST_OUTPUT_DIR="${OUTPUT_DIR}/transmission-time-${BENCH_TIME}-${payload}${protocol}"
			xecho "Performing benchmark, output ${TEST_OUTPUT_DIR}"
			[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"

			run_server "${protocol}"
			run_client "${protocol}" --send-ktls-time "${BENCH_TIME}" --payload ${payload} \
				--output "${TEST_OUTPUT_DIR}/ktls-output.${i}.json"
			stop_server
			run_server "${protocol}"
			run_client "${protocol}" --send-gnutls-time "${BENCH_TIME}" --payload ${payload} \
				--output "${TEST_OUTPUT_DIR}/gnutls-output.${i}.json"
			stop_server

			########## splice(2) - TIME
			TEST_OUTPUT_DIR="${OUTPUT_DIR}/splice-time-${BENCH_TIME}-dev-zero-${payload}${protocol}"
			xecho "Performing benchmark, output: ${TEST_OUTPUT_DIR}"
			[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"
			run_server "${protocol}" --no-echo
			run_client "${protocol}" --splice-time "${BENCH_TIME}" --payload ${payload} \
				--splice-file /dev/zero --output "${TEST_OUTPUT_DIR}/output.${i}.json"
			stop_server

			########### splice(2) echo -- "ping-pong" - TIME
			TEST_OUTPUT_DIR="${OUTPUT_DIR}/splice-echo-time-${BENCH_TIME}-${payload}${protocol}"
			xecho "Performing benchmark, output: ${TEST_OUTPUT_DIR}"
			[ -d "${TEST_OUTPUT_DIR}" ] || mkdir "${TEST_OUTPUT_DIR}"
			run_server "${protocol}" --mtu ${payload}
			run_client "${protocol}" --splice-echo-time "${BENCH_TIME}" --payload ${payload} \
				--sendfile-mtu ${SENDFILE_MTU} --output "${TEST_OUTPUT_DIR}/output.${i}.json"
			stop_server

		done

	done

done

for dir in "${OUTPUT_DIR}"/*; do
	find "${dir}" -iname '*.json' -exec python merge_output.py "${dir}/output.json" {} \+
done

xecho "Adding cpuinfo"
cat /proc/cpuinfo > "${OUTPUT_DIR}/cpuinfo"

for json in `find "${OUTPUT_DIR}" -iname 'output.json'`; do
	xecho "Generating HTML statistics for ${json}"
	outdir=`dirname "${json}"`
	./af_ktls-visualize/visualize.py --html-stats --input "${json}" --output-dir "${outdir}"
done

xecho "Generating Index"
python generate_index.py "${OUTPUT_DIR}"

