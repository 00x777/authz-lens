# Correctly scoped handlers: the analyzer must stay quiet on every one of these.
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Note, Invoice, Category, User
from .deps import get_db, get_current_user, authorize

router = APIRouter(prefix="/api")
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.get("/notes/{note_id}")
def read_note(note_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # scoped in the query itself
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user.id).first()
    if note is None:
        raise HTTPException(404)
    return note


@router.delete("/invoices/{invoice_id}")
def delete_invoice(invoice_id: int, user: CurrentUser, db: Session = Depends(get_db)):
    # load then explicit ownership check
    inv = db.get(Invoice, invoice_id)
    if inv is None or inv.account_id != user.account_id:
        raise HTTPException(404)
    db.delete(inv)


@router.put("/categories/{slug}")
def rename_category(slug: str, name: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # tenant id taken from the authenticated user, not from the request
    stmt = select(Category).where(Category.slug == slug, Category.group_id == user.group_id)
    cat = db.execute(stmt).scalar_one()
    cat.name = name


@router.get("/shared/{note_id}")
def read_shared(note_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # delegated to a policy function
    note = db.get(Note, note_id)
    authorize(user, "read", note)
    return note


@router.get("/me/notes")
def my_notes(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # no client-supplied identifier at all
    return db.query(Note).filter_by(owner_id=user.id).all()
