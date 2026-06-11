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
	echo "usage: sh scripts/run_gpt2_bench.sh [lamp|freivalds|lamp_gpt2|freivalds_gpt2|all] [--range] [flags...]" >&2
	echo "" >&2
	echo "examples:" >&2
	echo "  sh scripts/run_gpt2_bench.sh lamp" >&2
	echo "  sh scripts/run_gpt2_bench.sh freivalds" >&2
	echo "  sh scripts/run_gpt2_bench.sh all" >&2
	exit 2
}

if [ "$#" -lt 1 ]; then
	usage
fi

target="$1"
shift

case "$target" in
	lamp|lamp_gpt2|freivalds|freivalds_gpt2|all)
		;;
	*)
		usage
		;;
esac

args=""
for arg in "$@"; do
	if [ -z "$args" ]; then
		args="$arg"
	else
		args="$args $arg"
	fi
done

docker build -t "$image" .

env_args="--env-file .env"
for key in \
	LAMP_GPT2_SEQ LAMP_GPT2_RHO LAMP_GPT2_L LAMP_GPT2_ALL LAMP_GPT2_SEQ_FROM LAMP_GPT2_SEQ_TO LAMP_GPT2_ONLY_COMPILE LAMP_GPT2_OUTPUT_DIR \
	FREIVALDS_GPT2_SEQ FREIVALDS_GPT2_ALL FREIVALDS_GPT2_SEQ_FROM FREIVALDS_GPT2_SEQ_TO FREIVALDS_GPT2_ONLY_COMPILE FREIVALDS_GPT2_OUTPUT_DIR
do
	value="$(eval "printf '%s' \"\${$key:-}\"")"
	if [ -n "$value" ]; then
		env_args="$env_args -e $key=$value"
	fi
done

run_protocol() {
	protocol="$1"
	# shellcheck disable=SC2086
	docker run --rm $env_args \
		-v "$(pwd)/benchmark:/workspace/benchmark" \
		"$image" go run "./cmd/$protocol" $args
}

case "$target" in
	lamp|lamp_gpt2)
		run_protocol lamp_gpt2
		;;
	freivalds|freivalds_gpt2)
		run_protocol freivalds_gpt2
		;;
	all)
		run_protocol lamp_gpt2
		run_protocol freivalds_gpt2
		;;
esac
