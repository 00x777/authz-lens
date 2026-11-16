from fastapi import APIRouter, Depends, FastAPI

from .deps import get_current_user, get_admin
from .routes import notes, admin_panel
from .routes.public import router as public_router

app = FastAPI()
private = APIRouter(dependencies=[Depends(get_current_user)])
private.include_router(notes.router, prefix="/notes")
app.include_router(private)
app.include_router(admin_panel.router, dependencies=[Depends(get_admin)])
app.include_router(public_router)
