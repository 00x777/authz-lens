# No auth anywhere on this router.
from fastapi import APIRouter, Depends
from ..models import Note

router = APIRouter()


@router.get("/shared/{note_id}")
def shared(note_id: int, db=Depends(lambda: None)):
    return db.get(Note, note_id)
