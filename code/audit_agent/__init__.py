"""Ghost Data Still Exists - deletion audit agent.

A deterministic evidence reconciliation engine with an optional language-model
assistant used only for request-intent reading and for adjudicating
identifier collisions that the deterministic matcher flags as ambiguous.

Public entry point: :func:`pipeline.run`.
"""

__version__ = "1.0.0"
