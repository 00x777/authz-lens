# Deliberately vulnerable FastAPI app used as a test fixture. Never deploy.
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Note, Invoice, Category, User
from .deps import get_db, get_current_user

router = APIRouter(prefix="/api")


@router.get("/notes/{note_id}")
def read_note(note_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # VULN-1: authenticated, but any user can read any note (CWE-639)
    note = db.get(Note, note_id)
    if note is None:
        raise HTTPException(404)
    return note


@router.delete("/invoices/{invoice_id}")
async def delete_invoice(invoice_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # VULN-2: write path, filter only on primary key
    inv = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    db.delete(inv)
    db.commit()


@router.put("/categories/{slug}")
def rename_category(slug: str, group_id: int, name: str, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    # VULN-3: tenant filter exists but the tenant id comes from the client (cross-tenant write)
    stmt = select(Category).where(Category.slug == slug, Category.group_id == group_id)
    cat = db.execute(stmt).scalar_one()
    cat.name = name
    db.commit()


@router.get("/public/notes/{note_id}")
def read_note_unauthenticated(note_id: int, db: Session = Depends(get_db)):
    # VULN-4: no authentication at all (CWE-306)
    return db.get(Note, note_id)
