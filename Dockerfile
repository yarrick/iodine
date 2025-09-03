FROM gcc:12.4.0 AS build
COPY . /app
WORKDIR /app
RUN make && \
    make install && \
    apt update && \
    apt install net-tools
ENTRYPOINT /usr/local/sbin/iodine
CMD /usr/local/sbin/iodine
