# Auth comes from the parent router in main.py, but the handler never scopes the note.
from fastapi import APIRouter, Depends
from ..models import Note

router = APIRouter()


@router.get("/{note_id}")
def get_note(note_id: int, db=Depends(lambda: None)):
    return db.get(Note, note_id)
