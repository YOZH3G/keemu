# m1c-26 owner-scoped native firewall backend; never target PATH or host netns.
FROM debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      iptables=1.8.11-2 libxtables12=1.8.11-2 \
      libip4tc2=1.8.11-2 libip6tc2=1.8.11-2 \
      libmnl0=1.0.5-3 libnfnetlink0=1.0.2-3 \
      libnetfilter-conntrack3=1.1.0-1 libnftnl11=1.2.9-1 \
      netbase=6.5 libc6=2.41-12+deb13u4 && \
    test -x /usr/sbin/iptables-legacy && \
    test -f /usr/lib/x86_64-linux-gnu/xtables/libxt_NFQUEUE.so && \
    test -f /usr/lib/x86_64-linux-gnu/xtables/libxt_tcp.so
ENTRYPOINT ["/usr/sbin/iptables-legacy"]
