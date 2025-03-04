FROM amazonlinux:2

# Install Python, development tools, and Rust
RUN yum install python3 python3-devel gcc make iproute curl -y && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    source $HOME/.cargo/env

# Add Cargo to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

COPY requirements.txt ./
COPY enclave_server.py ./
COPY forwarder.py ./
COPY run.sh ./
COPY kmstool_enclave_cli ./
COPY libnsm.so /usr/lib64/
COPY kms.py ./
COPY nsm_interface.py ./
COPY vssspy/target/wheels/vssspy-0.1.0-cp37-cp37m-manylinux_2_24_x86_64.whl ./
COPY vssspy/ ./vssspy/
ENV REGION us-east-1
ENV AWS_REGION us-east-1
ENV AWS_DEFAULT_REGION us-east-1
RUN pip3 install -r requirements.txt

# Try to install from wheel first, if that fails build from source
RUN pip3 install ./vssspy-0.1.0-cp37-cp37m-manylinux_2_24_x86_64.whl || \
    (cd vssspy && pip3 install .)

RUN chmod +x kmstool_enclave_cli

RUN chmod +x run.sh
CMD ["/bin/bash", "/app/run.sh"]
