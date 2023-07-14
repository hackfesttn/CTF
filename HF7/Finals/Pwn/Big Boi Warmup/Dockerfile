FROM pwn.red/jail

COPY --from=ubuntu@sha256:554e40b15453c788ec799badf0f1ad05c3e5c735b53f940feb8f27cf2ec570c5 / /srv

COPY main /srv/app/run

COPY flag.txt /srv/app/
ENV JAIL_MEM=20M JAIL_POW=5000 JAIL_ENV_NUM=5 JAIL_TIME=200

EXPOSE 1337
