from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.security.auth import require_authenticated
from src.reporting.security_report import generate_security_report

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
    dependencies=[Depends(require_authenticated)],
)


@router.get("")
def get_report(db: Session = Depends(get_db)):
    return generate_security_report(db)
