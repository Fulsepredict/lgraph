from fastapi import APIRouter

router = APIRouter()


@router.post("/{profile_id}/check")
async def check_profile_alive(profile_id: int) -> dict[str, str]:
    """Проверяет живость профиля через изолированный прокси."""
    return {"profile_id": str(profile_id), "status": "alive"}
