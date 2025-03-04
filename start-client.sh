#!/bin/bash

# Activate the virtual environment
source venv/bin/activate

# Run the server using uvicorn
uvicorn host.app:app --host 0.0.0.0 --port 8001 --ssl-keyfile /home/ec2-user/certs/privkey.pem --ssl-certfile /home/ec2-user/certs/fullchain.pem
