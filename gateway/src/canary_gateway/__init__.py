"""Private authenticated canary gateway for the communication privacy benchmark.

AGPL-3.0-only. A separate distribution from the benchmark core on purpose: this is
long-lived lab infrastructure that a measurement job connects to, not code every job
installs. The two sides of the contract are written independently so that a disagreement
between them fails a test rather than producing a measurement that quietly did not happen.
"""

from canary_gateway.app import Settings, create_app
from canary_gateway.store import InMemoryObservationStore, ObservationStore

__all__ = ["InMemoryObservationStore", "ObservationStore", "Settings", "create_app"]
