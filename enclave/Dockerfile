FROM amazonlinux:2

RUN yum install python3 iproute -y

WORKDIR /app

COPY requirements.txt ./
COPY enclaveServer.py ./
COPY kmstool_enclave_cli ./
COPY libnsm.so /usr/lib64/
COPY kms.py ./
COPY NsmInterface.py ./
# you need set the ENV based on your environment
ENV REGION us-east-1
ENV AWS_REGION us-east-1
ENV AWS_DEFAULT_REGION us-east-1

RUN pip3 install -r requirements.txt

RUN chmod +x kmstool_enclave_cli

CMD ["python3", "/app/enclaveServer.py"]
