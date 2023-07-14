FROM pwn.red/jail

COPY --from=ubuntu@sha256:83f0c2a8d6f266d687d55b5cb1cb2201148eb7ac449e4202d9646b9083f1cee0  / /srv

COPY main /srv/app/run

COPY flag.txt /srv/app/
ENV JAIL_MEM=20M JAIL_POW=5000 JAIL_ENV_NUM=5 JAIL_TIME=200

EXPOSE 1338
