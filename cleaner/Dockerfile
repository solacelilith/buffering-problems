FROM ubuntu:24.04
COPY clean.sh /clean.sh
RUN chmod +x /clean.sh
USER nobody

ENTRYPOINT [ "/clean.sh" ]
