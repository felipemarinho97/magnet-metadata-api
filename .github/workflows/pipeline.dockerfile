#####################################################
### Copy platform specific binary
FROM bash AS copy-binary
ARG TARGETPLATFORM

RUN echo "Target Platform = ${TARGETPLATFORM}"

COPY dist .
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ];  then cp magnetmetadataapi_linux_amd64_linux_amd64_v1/magnet-metadata-api /magnet-metadata-api; fi
RUN if [ "$TARGETPLATFORM" = "linux/386" ];  then cp magnetmetadataapi_linux_386_linux_386_sse2/magnet-metadata-api /magnet-metadata-api; fi
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ];  then cp magnetmetadataapi_linux_arm64_linux_arm64_v8.0/magnet-metadata-api /magnet-metadata-api; fi
RUN if [ "$TARGETPLATFORM" = "linux/arm/v6" ]; then cp magnetmetadataapi_linux_arm_linux_arm_6/magnet-metadata-api /magnet-metadata-api; fi
RUN if [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then cp magnetmetadataapi_linux_arm_linux_arm_7/magnet-metadata-api /magnet-metadata-api; fi
RUN if [ "$TARGETPLATFORM" = "linux/riscv64" ]; then cp magnetmetadataapi_linux_riscv64_linux_riscv64_rva20u64/magnet-metadata-api /magnet-metadata-api; fi
RUN chmod +x /magnet-metadata-api


#####################################################
### Build Final Image
FROM alpine AS release
LABEL maintainer="felipevm97@gmail.com"

COPY --from=copy-binary /magnet-metadata-api /app/

WORKDIR /app

ENTRYPOINT ["/app/magnet-metadata-api"]