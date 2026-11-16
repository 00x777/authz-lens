# Admin-only via include_router(..., dependencies=[Depends(get_admin)]): should be quiet.
from fastapi import APIRouter, Depends
from ..models import Note

router = APIRouter()


@router.delete("/notes/{note_id}")
def admin_delete(note_id: int, db=Depends(lambda: None)):
    db.delete(db.get(Note, note_id))
