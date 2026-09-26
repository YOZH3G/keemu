#!/bin/sh
printf 'argc=%s\n' "$#"
printf 'arg1=<%s>\n' "${1-}"
printf 'arg2=<%s>\n' "${2-}"
