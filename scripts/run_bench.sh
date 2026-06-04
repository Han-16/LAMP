#!/usr/bin/env sh
set -eu

if [ ! -f .env ]; then
	echo "missing .env; create it from .env.example first" >&2
	exit 2
fi

set -a
. ./.env
set +a

image="${MEOWGO_DOCKER_IMAGE:-meowgo}"

usage() {
	echo "usage: scripts/run_bench.sh [meow|freivalds|all] [--range] [flags...]" >&2
	echo "" >&2
	echo "examples:" >&2
	echo "  scripts/run_bench.sh meow --K 10 --L 128" >&2
	echo "  scripts/run_bench.sh meow --K 10 --L 128 --merkle multi" >&2
	echo "  scripts/run_bench.sh freivalds --K 10 --compile" >&2
	echo "  scripts/run_bench.sh all --range --compile" >&2
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
	meow|freivalds|all)
		;;
	*)
		usage
		;;
esac

docker build -t "$image" .

env_args="--env-file .env"

for key in \
	MEOW_LOG_K MEOW_RHO MEOW_L MEOW_MERKLE MEOW_ALL MEOW_ONLY_COMPILE MEOW_OUTPUT_DIR MEOW_LOG_K_FROM MEOW_LOG_K_TO \
	FREIVALDS_LOG_K FREIVALDS_ALL FREIVALDS_ONLY_COMPILE FREIVALDS_OUTPUT_DIR FREIVALDS_LOG_K_FROM FREIVALDS_LOG_K_TO
do
	value="$(eval "printf '%s' \"\${$key:-}\"")"
	if [ -n "$value" ]; then
		env_args="$env_args -e $key=$value"
	fi
done

run_protocol() {
	protocol="$1"
	protocol_args="$args"
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
	meow)
		run_protocol meow
		;;
	freivalds)
		run_protocol freivalds
		;;
	all)
		run_protocol meow
		run_protocol freivalds
		;;
esac
