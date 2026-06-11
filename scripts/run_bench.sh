#!/usr/bin/env sh
set -eu

if [ ! -f .env ]; then
	echo "missing .env; create it from .env.example first" >&2
	exit 2
fi

set -a
. ./.env
set +a

image="${LAMP_DOCKER_IMAGE:-lamp}"

usage() {
	echo "usage: scripts/run_bench.sh [lamp|lamp_batch|freivalds|freivalds_batch|all] [--range] [flags...]" >&2
	echo "" >&2
	echo "examples:" >&2
	echo "  scripts/run_bench.sh lamp" >&2
	echo "  scripts/run_bench.sh lamp_batch" >&2
	echo "  scripts/run_bench.sh freivalds" >&2
	echo "  scripts/run_bench.sh freivalds_batch" >&2
	echo "  scripts/run_bench.sh all" >&2
	exit 2
}

if [ "$#" -lt 1 ]; then
	usage
fi

target="$1"
shift

range=false
args=""
for arg in "$@"; do
	case "$arg" in
		--range)
			range=true
			;;
		*)
			if [ -z "$args" ]; then
				args="$arg"
			else
				args="$args $arg"
			fi
			;;
	esac
done

case "$target" in
	lamp|lamp_batch|freivalds|freivalds_batch|all)
		;;
	*)
		usage
		;;
esac

docker build -t "$image" .

env_args="--env-file .env"

for key in \
	LAMP_LOG_K LAMP_RHO LAMP_L LAMP_ALL LAMP_ONLY_COMPILE LAMP_OUTPUT_DIR LAMP_LOG_K_FROM LAMP_LOG_K_TO \
	LAMP_BATCH_LOG_K LAMP_BATCH_RHO LAMP_BATCH_L LAMP_BATCH_SIZE LAMP_BATCH_ALL LAMP_BATCH_RANGE LAMP_BATCH_ONLY_COMPILE LAMP_BATCH_OUTPUT_DIR LAMP_BATCH_LOG_K_FROM LAMP_BATCH_LOG_K_TO LAMP_BATCH_FROM LAMP_BATCH_TO \
	FREIVALDS_LOG_K FREIVALDS_ALL FREIVALDS_ONLY_COMPILE FREIVALDS_OUTPUT_DIR FREIVALDS_LOG_K_FROM FREIVALDS_LOG_K_TO \
	FREIVALDS_BATCH_LOG_K FREIVALDS_BATCH_SIZE FREIVALDS_BATCH_ALL FREIVALDS_BATCH_RANGE FREIVALDS_BATCH_ONLY_COMPILE FREIVALDS_BATCH_OUTPUT_DIR FREIVALDS_BATCH_LOG_K_FROM FREIVALDS_BATCH_LOG_K_TO FREIVALDS_BATCH_FROM FREIVALDS_BATCH_TO
do
	value="$(eval "printf '%s' \"\${$key:-}\"")"
	if [ -n "$value" ]; then
		env_args="$env_args -e $key=$value"
	fi
done

output_dir_for() {
	case "$1" in
		lamp)
			printf '%s\n' "${LAMP_OUTPUT_DIR:-benchmark/lamp}"
			;;
		lamp_batch)
			printf '%s\n' "${LAMP_BATCH_OUTPUT_DIR:-benchmark/lamp_batch}"
			;;
		freivalds)
			printf '%s\n' "${FREIVALDS_OUTPUT_DIR:-benchmark/freivalds}"
			;;
		freivalds_batch)
			printf '%s\n' "${FREIVALDS_BATCH_OUTPUT_DIR:-benchmark/freivalds_batch}"
			;;
	esac
}

run_protocol() {
	protocol="$1"
	protocol_args="$args"
	output_dir="$(output_dir_for "$protocol")"
	if [ -n "$output_dir" ]; then
		mkdir -p "$output_dir"
	fi

	if [ "$range" = true ]; then
		if [ -z "$protocol_args" ]; then
			protocol_args="--all"
		else
			protocol_args="--all $protocol_args"
		fi
	fi

	# shellcheck disable=SC2086
	docker run --rm $env_args \
		-v "$(pwd)/benchmark:/workspace/benchmark" \
		"$image" go run "./cmd/$protocol" $protocol_args
}

case "$target" in
	lamp)
		run_protocol lamp
		;;
	lamp_batch)
		run_protocol lamp_batch
		;;
	freivalds)
		run_protocol freivalds
		;;
	freivalds_batch)
		run_protocol freivalds_batch
		;;
	all)
		run_protocol lamp
		run_protocol lamp_batch
		run_protocol freivalds
		run_protocol freivalds_batch
		;;
esac
