"""Shared pytest fixtures for all integration tests.

Authentication-related fixtures use lazy imports so that
test_registration.py can run before the authentication/ package exists.
"""

import pytest

from ledger.ledger import Ledger
from node.node import Node
from node.transport import LocalTransport
from registration.register import RegistrationService


@pytest.fixture
def nodes(tmp_path):
    """5 Node instances sharing the same data directory."""
    return [Node(node_id=i, data_dir=str(tmp_path)) for i in range(1, 6)]


@pytest.fixture
def transport(nodes):
    """LocalTransport with all 5 nodes registered."""
    t = LocalTransport()
    for n in nodes:
        t.register_node(n.node_id, n)
    return t


@pytest.fixture
def ledger(tmp_path):
    """Fresh append-only ledger backed by a temp SQLite file."""
    return Ledger(db_path=str(tmp_path / "ledger.db"))


@pytest.fixture
def challenge_manager():
    from authentication.challenge import ChallengeManager
    return ChallengeManager()


@pytest.fixture
def registration_service(nodes, ledger, tmp_path):
    return RegistrationService(nodes=nodes, ledger=ledger, data_dir=str(tmp_path))


@pytest.fixture
def authentication_service(nodes, ledger, challenge_manager, transport, tmp_path):
    import authentication.iat as _iat_module
    from authentication.authenticate import AuthenticationService
    _iat_module.init_system_keys(str(tmp_path))
    return AuthenticationService(
        nodes=nodes,
        ledger=ledger,
        challenge_manager=challenge_manager,
        transport=transport,
        data_dir=str(tmp_path),
    )
