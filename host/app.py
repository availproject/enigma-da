from fastapi import FastAPI
from host.routes import register_routes

app = FastAPI()
register_routes(app)