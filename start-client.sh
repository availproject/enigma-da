#!/bin/bash

# Activate the virtual environment
source venv/bin/activate

# Run the server using uvicorn
uvicorn host.app:app --reload --host 0.0.0.0 --port 8001