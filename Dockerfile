FROM openjdk:8u242-slim
COPY . .
RUN mv jq-linux64 /usr/local/bin/jq && mv cert-expiry-checker /usr/local/bin/ && \
    chmod +x  /usr/local/bin/jq  /usr/local/bin/cert-expiry-checker

ENTRYPOINT [ "cert-expiry-checker","--config","/config.json" ]