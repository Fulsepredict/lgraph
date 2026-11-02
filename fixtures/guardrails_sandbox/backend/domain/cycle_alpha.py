from backend.domain.cycle_beta import beta_calc


def alpha_calc() -> int:
    return beta_calc() + 1
