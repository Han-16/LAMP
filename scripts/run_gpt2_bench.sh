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
range=false
for arg in "$@"; do
	case "$arg" in
		--range|--all)
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

# Share the RHO -> L mapping with the regular LAMP benchmarks.
rho="${RHO:-${LAMP_GPT2_RHO:-1/2}}"
explicit_l="${LAMP_GPT2_L:-}"
expect_l=false
expect_rho=false
for arg in "$@"; do
	if [ "$expect_l" = true ]; then explicit_l="$arg"; expect_l=false; continue; fi
	if [ "$expect_rho" = true ]; then rho="$arg"; expect_rho=false; continue; fi
	case "$arg" in
		-L|--L) expect_l=true ;;
		-L=*|--L=*) explicit_l="${arg#*=}" ;;
		--rho=*|-rho=*) rho="${arg#*=}" ;;
		--rho|-rho) expect_rho=true ;;
	esac
done
case "$rho" in
	1/2) default_l=309 ;;
	1/4) default_l=189 ;;
	1/8) default_l=155 ;;
	*) echo "unsupported RHO: $rho" >&2; exit 2 ;;
esac
[ -n "$explicit_l" ] || explicit_l="$default_l"
LAMP_GPT2_RHO="$rho"
LAMP_GPT2_L="$explicit_l"
export LAMP_GPT2_RHO LAMP_GPT2_L

is_true() {
	case "${1:-}" in
		1|true|TRUE|yes|YES|on|ON) return 0 ;;
		*) return 1 ;;
	esac
}

flag_value() {
	wanted="$1"
	value="$2"
	shift 2
	want_value=false
	for arg in "$@"; do
		if [ "$want_value" = true ]; then
			value="$arg"
			want_value=false
			continue
		fi
		case "$arg" in
			"$wanted") want_value=true ;;
			"$wanted"=*) value="${arg#*=}" ;;
		esac
	done
	printf '%s\n' "$value"
}

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

run_process() {
	protocol="$1"
	append_results="$2"
	shift 2
	# Calls are intentionally sequential and unconstrained so this one
	# benchmark process can use all resources available to Docker.
	# shellcheck disable=SC2086
	docker run --rm $env_args \
		-e BENCHMARK_APPEND_CSV="$append_results" \
		-v "$(pwd)/benchmark:/workspace/benchmark" \
		"$image" "/usr/local/bin/$protocol" $args "$@"
}

run_protocol() {
	protocol="$1"
	protocol_range="$range"
	case "$protocol" in
		lamp_gpt2)
			is_true "${LAMP_GPT2_ALL:-false}" && protocol_range=true
			seq="$(flag_value --seq "${LAMP_GPT2_SEQ:-1}" $args)"
			seq_from="$(flag_value --from "${LAMP_GPT2_SEQ_FROM:-0}" $args)"
			seq_to="$(flag_value --to "${LAMP_GPT2_SEQ_TO:-4}" $args)"
			;;
		freivalds_gpt2)
			is_true "${FREIVALDS_GPT2_ALL:-false}" && protocol_range=true
			seq="$(flag_value --seq "${FREIVALDS_GPT2_SEQ:-1}" $args)"
			seq_from="$(flag_value --from "${FREIVALDS_GPT2_SEQ_FROM:-0}" $args)"
			seq_to="$(flag_value --to "${FREIVALDS_GPT2_SEQ_TO:-4}" $args)"
			;;
	esac

	if [ "$protocol_range" = false ]; then
		run_process "$protocol" false --all=false --range=false
		return
	fi

	append_results=false
	current_seq="$seq_from"
	while [ "$current_seq" -le "$seq_to" ]; do
		run_process "$protocol" "$append_results" --all=false --range=false --seq "$current_seq"
		append_results=true
		current_seq=$((current_seq + 1))
	done
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
