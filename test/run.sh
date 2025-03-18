#!/bin/bash

target_ip="127.0.0.1"
target_port=53
timeout=1

threads=10
failstop=0
copynew=0
debug=0

SED="sed"
if [ "`uname -s`" == "Darwin" ]; then SED="gsed"; fi

timestamp="`date +%y%m%d_%H%M%S`"
last_test_run_dir="`ls -d /tmp/polardns_* 2>/dev/null | sort | tail -1`"
this_test_run_dir="/tmp/polardns_${timestamp}_$$$RANDOM$$"
del_my_test_run_dir=0

testroot="`dirname $0`"
dig_out_ref="${testroot}/dig-out"
dig_out_ref_ok="${testroot}/dig-out-sanitized"
dig_out_now="${this_test_run_dir}/dig-out"
dig_out_now_ok="${this_test_run_dir}/dig-out-sanitized"

trap "eval_results "${this_test_run_dir}"; rm -rf -- \"${this_test_run_dir}\"; kill -9 $$" INT

#######################################
domain=""

# get the domain name from the config file
config="polardns.toml"
if [ ! -f "${config}" ]; then
  config="../polardns.toml"
  if [ ! -f "${config}" ]; then
    config="polardns/polardns.toml"
  fi
fi
domain="`grep -v '^#' ${config} | grep -m1 "domain = " | awk '{print $3}' | cut -f2 -d"'"`"
if [ "${domain}" == "" ]; then
  echo "ERROR: cannot load domain name"
  exit 1
fi

#######################################

sanitize_filename() {
  local text="$*"
  local sanitized
  sanitized=$(echo "$text" | sed 's/[^a-zA-Z0-9._]/_/g')
  echo "${sanitized:0:250}"
}

sanitize_dig_output() {
  grep -v '^; <<>> DiG \| WHEN: \| Query time: ' \
  | ${SED} -e 's/, id: .*/, id: <ID>/;s/expected ID .*, got .*/expected ID <ID>, got <DIF>/' \
  | ${SED} -e 's/\x09\s*/ /g;s/\\000/<NUL>/g;s/\([^0-9]\)[0-9]\{6\}\([^0-9]\)/\1<RANDOM>\2/' \
  | ${SED} -e 's/rcvd: .*/rcvd: <SIZE>/;s/has [0-9]* extra bytes/has <NUM> extra bytes/g' \
  | ${SED} -e "s/${domain//\./\\.}/<OURDOM>/g;s/${domain%.*}/<OURDOM-NOTLD>/g" \
  | ${SED} -E 's/(SRV\s*0\s*0\s*)[0-9]*\s*(_.*sr|sr|)(loop|chain|alias)/\1 <PORT> \2\3/g' \
  | ${SED} -E 's/(CNAME|DNAME|HTTPS|SVCB|SRV|MX|NS|TXT)(.*)(:|\s|cn|dn|ht|sv|sr|mx|ns|spf)alias[0-9]+\./\1\2\3alias<RANDOM>\./g' \
  | ${SED} -e 's/alias[0-9]\+/alias<RANDOM>/g;s/\(\.10\.in-addr\.arpa\..*PTR\s*\)[0-9]\+\.[0-9]\+\./\1<RANDOM>.<RANDOM>./g' \
  | ${SED} -e '0,/^\([0-9a-f]\{2\} \)\{16\} /s/^\([0-9a-f]\{2\} \)\{2\}\(\([0-9a-f]\{2\} \)\{14\} *\)[^ ][^ ]/TX ID \2ID/1' \
  | ${SED} -e "s/#${target_port}/#53/g;s/${target_ip}/127\.0\.0\.1/g;s/^\(size.*127\.0\.0\.\).*$/\1<RANDOM>/g" \
  | ${SED} -e 's/!1\.\([0-9]\+\.\)\+\(e164\.arpa!" \.\)/!1.<RANDOM>.\2/'
}

#######################################

runtest() {
  dom="$1"

  cmdfn="dig_`sanitize_filename "${dom}"`.out"

  out="${dig_out_now}/${cmdfn}"
  out_sanitized="${dig_out_now_ok}/${cmdfn}" # current dig output
  ref_sanitized="${dig_out_ref_ok}/${cmdfn}" # reference dig output

  dig_cmd="dig ${dom} @${target_ip} +tries=1 +timeout=${timeout} -p ${target_port}"
  ${dig_cmd} &>"${out}"
  sanitize_dig_output <"${out}" &>"${out_sanitized}"

  diff -q "${ref_sanitized}" "${out_sanitized}" &>/dev/null
  result=$?

  echo "${dom}" >>"${this_test_run_dir}/tests.executed"
  if [ ! -f "${ref_sanitized}" ]; then
    if [ $((copynew)) -eq 0 ]; then
      echo "${dom}" >>"${this_test_run_dir}/tests.new"
      echo "NEW   dig ${dom}"
      echo "      ${dig_cmd}"
      echo "Reference file '${ref_sanitized}' does not exist."
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output:"
      cat ${out}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output (sanitized):"
      cat ${out_sanitized}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Use -c to save the current dig output as reference."
      echo "-------------------------------------"
    else
      echo "${dom}" >>"${this_test_run_dir}/tests.added"
      echo "ADDED dig ${dom}"
      cp -p -- "${out}" "${dig_out_ref}"
      cp -p -- "${out_sanitized}" "${dig_out_ref_ok}"
    fi
  elif [ $((result)) -ne 0 ]; then
    echo "${dom}" >>"${this_test_run_dir}/tests.failed"
    echo "FAIL  dig ${dom}"
    echo "      ${dig_cmd}"
    echo "      diff ${ref_sanitized} ${out_sanitized}"
    if [ $((debug)) -eq 1 ]; then
      diff ${ref_sanitized} ${out_sanitized}
      echo "-------------------------------------"
    elif [ $((debug)) -eq 2 ]; then
      diff -y ${ref_sanitized} ${out_sanitized}
      echo "-------------------------------------"
    elif [ $((debug)) -eq 3 ]; then
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output (sanitized):"
      cat ${out_sanitized}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Reference dig output (sanitized):"
      cat ${ref_sanitized}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Comparison:"
      diff -y --color ${ref_sanitized} ${out_sanitized}
      echo "-------------------------------------"
    elif [ $((debug)) -gt 3 ]; then
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output:"
      cat ${out}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output (sanitized):"
      cat ${out_sanitized}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Reference dig output (sanitized):"
      cat ${ref_sanitized}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Comparison:"
      diff -y --color ${ref_sanitized} ${out_sanitized}
      echo "-------------------------------------"
    fi
    if [ $((failstop)) -eq 1 ]; then
      exit 1
    fi
  else
    echo "${dom}" >>"${this_test_run_dir}/tests.passed"
    echo "PASS  dig ${dom}"
    if [ $((debug)) -gt 3 ]; then
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output:"
      cat ${out}
      echo "- - - - - - - - - - - - - - - - - - -"
      echo "Got dig output (sanitized):"
      cat ${out_sanitized}
      echo "-------------------------------------"
    elif [ $((debug)) -gt 2 ]; then
      echo "- - - - - - - - - - - - - - - - - - -"
      cat ${out_sanitized}
      echo "-------------------------------------"
      #diff -y ${ref_sanitized} ${out_sanitized}
    fi
  fi
}

#######################################

eval_results() {
  test_run_dir="$1"

  testcount=`wc -l "${test_run_dir}/tests.executed" | awk '{print $1}'`
  passcount=`wc -l "${test_run_dir}/tests.passed" | awk '{print $1}'`
  failcount=`wc -l "${test_run_dir}/tests.failed" | awk '{print $1}'`
  addcount=`wc -l "${test_run_dir}/tests.added" | awk '{print $1}'`
  newcount=`wc -l "${test_run_dir}/tests.new" | awk '{print $1}'`
  
  echo
  echo "TESTS: ${testcount}"
  echo " PASS: ${passcount}"
  echo " FAIL: ${failcount}"
  if [ $((newcount)) -gt 0 ]; then echo "  NEW: ${newcount}"; fi
  if [ $((addcount)) -gt 0 ]; then echo "ADDED: ${addcount}"; fi
}

#######################################

usage() {
  cat <<EOF

=== PolarDNS test runner ===

Usage: `basename $0` [OPTION] [failed|new|/path/to/tests.suite]

Available options:

 -s  stop after first failed test
 -d  increase debug level (up to -dddd)
 -c  copy dig output of NEW tests into repository

----------------------------------------
Use-cases:

$0
     run all tests

$0 failed
     will re-run only the previously failed tests

$0 -dddd failed
     will re-run only the previously failed tests with the highest debug level

$0 new
     will re-run only the previously new tests

$0 -c new
     will add the new tests to reference repository

$0 path/to/tests.suite
     will run only the specific test suite

$0 test/tests.injections
     will run only the test suite for record injections

EOF
}

#######################################
# main

# cleanup & prep
{ mkdir -p -- "${dig_out_ref}"
  mkdir -p -- "${dig_out_ref_ok}"
  mkdir -p -- "${dig_out_now}"
  mkdir -p -- "${dig_out_now_ok}"
  mkdir -p -- "${this_test_run_dir}"
  touch -- "${this_test_run_dir}/tests.executed"
  touch -- "${this_test_run_dir}/tests.passed"
  touch -- "${this_test_run_dir}/tests.failed"
  touch -- "${this_test_run_dir}/tests.added"
  touch -- "${this_test_run_dir}/tests.new"
} &>/dev/null

#######################################
# tests to run

torun=(
  ${testroot}/tests.general
  ${testroot}/tests.header_manipulation
  ${testroot}/tests.packet_manipulation
  ${testroot}/tests.aliases
  ${testroot}/tests.chains
  ${testroot}/tests.loops
  ${testroot}/tests.injections
  ${testroot}/tests.fuzzing
  ${testroot}/tests.empty
)

#######################################
# process arguments

while getopts "hsdc" opt; do
  case "$opt" in
    h)
       usage
       exit 0
       ;;
    s)
       failstop=1
       ;;
    d)
       ((debug++))
       ;;
    c)
       copynew=1
       ;;
    *)
       usage
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

if [ "${1}" == "dig" ]; then
  # run a single test
  shift
  runtest "${*}"
  exit 0
elif [ "${1}" == "failed" ]; then
  # run previously failed tests
  threads=1
  del_my_test_run_dir=1
  torun=("${last_test_run_dir}/tests.failed")
elif [ "${1}" == "new" ]; then
  # run previously new tests
  threads=1
  del_my_test_run_dir=1
  torun=("${last_test_run_dir}/tests.new")
elif [ -f "${1}" ] && [ "${1/\/tests./}" != "${1}" ]; then
  # run particular test suite
  torun=("${1}")
elif [ ! -z "${1}" ]; then
  # run a single test
  runtest "${*}"
  exit 0
fi

#######################################
# run tests

if [ $((threads)) -gt 1 ]; then
  # multi thread
  declare -a slots
  for tests in ${torun[*]}; do
    cat ${tests}
  done | tr -d '\r' | grep -v '^#\|^$' | while read testcase; do
    testcase="${testcase//\$\{domain\}/$domain}"
    freeslot=
    while :; do
      for ((j=0; j<$((threads)); j++)) {
        if [ $((${slots[$j]})) -eq 0 ]; then freeslot=$j; break 2; fi
        kill -0 ${slots[$j]} &>/dev/null
        if [ $? -eq 1 ]; then freeslot=$j; break 2; fi
      }
      sleep 0.1
    done
    runtest "${testcase}" &
    slots[${freeslot}]=$!
  done
  
  sleep 1
  wait &>/dev/null
else
  # single thread
  for tests in ${torun[*]}; do
    cat ${tests}
  done | tr -d '\r' | grep -v '^#\|^$' | while read testcase; do
    runtest "${testcase}"
  done
fi

#######################################
# eval results

eval_results "${this_test_run_dir}"

if [ $((del_my_test_run_dir)) -eq 1 ]; then
  rm -rf -- "${this_test_run_dir}"
fi
