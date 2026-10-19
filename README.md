# Veil: verified pseudonymisation for LLM calls

Real values are detected and replaced inside the branch, the external model sees only surrogates, and the values are restored locally. Every outbound payload is checked before it leaves. The design and its research basis are in [DESIGN.md](DESIGN.md).

```python
from sandwich import Sandwich, BranchDictionary, Entity

clients = BranchDictionary([Entity("c1", "PERSON", ["Sara Al Mansoori", "سارة المنصوري"])])
session = Sandwich(branch_key, clients).session()

p = session.protect("Email Sara Al Mansoori, ID 784-1985-1234567-4")
# p.outbound -> "Email [PERSON_1], ID 784-0326-8154733-2"   (FF1, Luhn-valid)
if p.blocked: ...                       # hard line found a value it could not scrub
reply = call_llm(session.llm_history)   # pseudonymised context only
shown, report = session.receive(reply)  # restored for display; report flags invented tags
session.close()                         # wipes keys and mapping
```

```
uv run pytest                     # unit tests incl. NIST FF1 vectors
uv run python bench/run.py        # synthetic UAE benchmark, Wilson 95% CIs
```

Phase 1 is the deterministic core: no model, synthetic data only.
