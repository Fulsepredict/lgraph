from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class OrderSummary(BaseModel):
    order_id: int
    status: str


@router.get("/{order_id}")
async def get_order(order_id: int) -> OrderSummary:
    """Возвращает карточку заказа по его номеру."""
    return OrderSummary(order_id=order_id, status="ready")


@router.post("/{order_id}/confirm")
async def confirm_order(order_id: int) -> OrderSummary:
    """Подтверждает оплату и сборку заказа."""
    return OrderSummary(order_id=order_id, status="confirmed")


@router.delete("/{order_id}")
async def cancel_order(order_id: int) -> dict[str, bool]:
    """Негативный кейс для Precision: этот DELETE-маршрут нигде не вызывается во фронтенде."""
    return {"cancelled": True}
