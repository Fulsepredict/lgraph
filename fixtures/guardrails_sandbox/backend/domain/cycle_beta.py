from backend.domain.cycle_alpha import alpha_calc


def beta_calc() -> int:
    return alpha_calc() + 1
