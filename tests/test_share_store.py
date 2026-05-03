import pytest
from node.share_store import ShareStore


@pytest.fixture
def store(tmp_path):
    return ShareStore(node_id=1, data_dir=str(tmp_path))


_DID = "did:decidp:testuser"
_X = 1
_Y = 0xDEADBEEFCAFEBABE * 10**30 + 1  # large field element


def test_store_and_retrieve(store):
    store.store_share(_DID, _X, _Y)
    x, y = store.get_share(_DID)
    assert x == _X
    assert y == _Y


def test_missing_did_returns_none(store):
    assert store.get_share("did:decidp:nobody") is None


def test_delete(store):
    store.store_share(_DID, _X, _Y)
    assert store.has_share(_DID)
    store.delete_share(_DID)
    assert store.get_share(_DID) is None
    assert not store.has_share(_DID)


def test_delete_nonexistent_is_noop(store):
    store.delete_share("did:decidp:ghost")  # must not raise


def test_has_share_true(store):
    store.store_share(_DID, _X, _Y)
    assert store.has_share(_DID)


def test_has_share_false(store):
    assert not store.has_share(_DID)


def test_replace_share(store):
    store.store_share(_DID, _X, _Y)
    new_y = _Y + 1
    store.store_share(_DID, _X, new_y)
    _, y = store.get_share(_DID)
    assert y == new_y


def test_feldman_commitment_stored(store):
    commitment = b"\xab" * 32
    store.store_share(_DID, _X, _Y, feldman_commitment=commitment)
    # Verify share still retrieves correctly when commitment is present
    x, y = store.get_share(_DID)
    assert x == _X and y == _Y


def test_integrity_failure_raises(store):
    store.store_share(_DID, _X, _Y)
    # Corrupt the share_hash directly in SQLite
    store.conn.execute(
        "UPDATE shares SET share_hash = ? WHERE did = ?",
        ("0" * 64, _DID),
    )
    store.conn.commit()
    with pytest.raises(ValueError, match="integrity"):
        store.get_share(_DID)


def test_multiple_dids(store):
    dids = [f"did:decidp:user{i}" for i in range(5)]
    for i, did in enumerate(dids, start=1):
        store.store_share(did, i, _Y + i)
    for i, did in enumerate(dids, start=1):
        x, y = store.get_share(did)
        assert x == i
        assert y == _Y + i


def test_key_persists_across_instances(tmp_path):
    store1 = ShareStore(node_id=2, data_dir=str(tmp_path))
    store1.store_share(_DID, _X, _Y)

    store2 = ShareStore(node_id=2, data_dir=str(tmp_path))
    x, y = store2.get_share(_DID)
    assert x == _X and y == _Y
