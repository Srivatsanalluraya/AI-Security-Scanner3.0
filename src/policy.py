def decide_outcome(overall: str, policy: str = "default") -> str:
    """
    Return one of: allow | monitor | block
    `overall` is one of: none, low, medium, high
    """
    policy = policy.lower()
    if policy == "default":
        # Your workflow: allow when HIGH; flag when LOW/MED
        return "allow" if overall == "high" else "monitor"

    if policy == "block_on_high":
        return "block" if overall == "high" else "allow"

    if policy == "block_on_low":
        return "block" if overall in {"low", "medium", "high"} else "allow"

    if policy == "monitor_only":
        return "monitor"

    return "monitor"

