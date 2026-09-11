"""The supervisor kernel, split by lifecycle phase (board #1630).

`git_supervisor.py` was one 9,000-line module holding a 7,900-line class, so no reviewer
could hold an integration or cleanup path in their head well enough to check the fencing
and trust claims that ARE this product. Each module here is lifted out of it verbatim.
`agent_control_plane.git_supervisor` re-exports everything it exported before, which
scripts/check_public_surface.py pins.
"""
