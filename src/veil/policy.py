"""Pre-flight policy gate: Green / Amber / Red tiers per tenant.

The calling app sends its classification label (from Pulse) in `x-veil-classification`;
absent, the tenant's default_label applies. Veil then raises it to what it detects:
  - any sensitive value found           -> at least Amber (Green requests are not trusted blindly)
  - any type in the tenant's red_types  -> Red (e.g. HEALTH for a tenant that requires it)
The label is only ever raised, never lowered.

Decision:
  effective <= ceiling            -> forward (pseudonymised) to the approved upstream
  effective >  ceiling, red route -> forward the ORIGINAL request to the tenant's verified
                                     in-branch model (it never leaves the branch)
  effective >  ceiling, no route  -> hand off to a person (request stopped, handoff id issued)
Classification is risk reduction, not a guarantee: it relies on detection, which has
measured miss rates (see RESULTS.md).
"""

from __future__ import annotations

from dataclasses import dataclass

from .tenancy import TIERS, Tenant

RANK = {t: i for i, t in enumerate(TIERS)}


@dataclass(frozen=True)
class Decision:
    label: str  # what the app said
    effective: str  # after Veil's floor
    action: str  # forward | red_local | handoff
    reason: str


def classify(tenant: Tenant, label: str | None, detected: dict[str, int]) -> Decision:
    given = (label or tenant.default_label).lower()
    if given not in RANK:
        given = tenant.default_label
    effective, reasons = given, []
    if any(detected.values()) and RANK[effective] < RANK["amber"]:
        effective, reasons = "amber", reasons + ["sensitive values detected"]
    red_hits = sorted(t for t, n in detected.items() if n and t in tenant.red_types)
    if red_hits:
        effective, reasons = "red", reasons + [f"red types detected: {','.join(red_hits)}"]
    if RANK[effective] <= RANK[tenant.ceiling]:
        return Decision(given, effective, "forward", "; ".join(reasons) or "within ceiling")
    why = "; ".join(reasons) or f"label {given} above ceiling {tenant.ceiling}"
    if tenant.red_upstream:
        return Decision(given, effective, "red_local", why)
    return Decision(given, effective, "handoff", why)
