FROM public.ecr.aws/amazonlinux/amazonlinux:minimal

RUN dnf install python3 iproute   -y

WORKDIR /app

RUN pip3 install eciespy

COPY enclave/server.py ./
COPY enclave/handlers.py ./
COPY enclave/run.sh ./

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]