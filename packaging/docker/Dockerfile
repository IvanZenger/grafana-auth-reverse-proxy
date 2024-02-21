FROM linux-docker-local.repo.pnet.ch/pf/alpine:3.19.202402181503

ARG http_proxy=http://outapplpf.pnet.ch:3128
ARG https_proxy=http://outapplpf.pnet.ch:3128
ARG no_proxy=localhost,127.0.0.1,.pnet.ch
ARG TZ=Europe/Zurich

ENV TZ=${TZ}

RUN apk add --no-cache tzdata


COPY grafana-auth-reverse-proxy /usr/bin/grafana-auth-reverse-proxy
COPY packaging/docker/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 755 /docker-entrypoint.sh

USER 65534

CMD ["--help"]
ENTRYPOINT ["/docker-entrypoint.sh"]
