from fastapi import APIRouter
from host.models import RegisterRequest

router = APIRouter()

# Home route
@router.get("/")
async def home():
    return "Welcome to Encifher!"

# Route to register an app with this service
@router.post("/register")
async def register_app(req: RegisterRequest):
    

# Route to encrypt data
@router.post("/encrypt")
async def encrypt_data():


# Register the routes with FastAPI
def register_routes(app):
    app.include_router(router)
