FROM scratch
LABEL org.opencontainers.image.authors="Hsn723" \
      org.opencontainers.image.title="cert-estuary" \
      org.opencontainers.image.source="https://github.com/hsn723/cert-estuary"
WORKDIR /
COPY cert-estuary /
COPY LICENSE /LICENSE
USER 65532:65532

ENTRYPOINT ["/cert-estuary"]
