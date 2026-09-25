# Bounded m1c-26 host module preparation; run network-none, exact files only.
FROM debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends kmod=34.2-2 && test -x /sbin/insmod
ENTRYPOINT ["/sbin/insmod"]
