FROM public.ecr.aws/amazonlinux/amazonlinux:minimal

RUN dnf install python3 iproute   -y

WORKDIR /app

RUN pip3 install eciespy

COPY enclave/handlers.py ./
COPY enclave/forwarder.py ./
COPY enclave/run.sh ./
COPY enclave/server.py ./
COPY enclave/vssspy/target/wheels/vssspy-0.1.0-cp39-cp39-manylinux_2_24_x86_64.whl ./

RUN pip3 install ./vssspy-0.1.0-cp39-cp39-manylinux_2_24_x86_64.whl

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]