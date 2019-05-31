FROM alpine:3.9

ADD requirements.txt /

RUN apk add python3 gcc musl-dev linux-headers python3-dev make libffi-dev openssl-dev g++ libtool m4 libuv-dev automake autoconf && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del gcc musl-dev linux-headers python3-dev make libffi-dev openssl-dev g++ libtool m4 libuv-dev automake autoconf && \
    rm -rf /var/cache/apk/*

ADD pytacacs_plus /app/pytacacs_plus
ADD scripts/pytacacs.py /app/

ENTRYPOINT ["/app/pytacacs.py"]
# ENTRYPOINT ["/bin/sh"]