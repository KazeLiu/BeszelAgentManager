"""Optional wire-format check against python-tuf; not an application dependency.

Input/output are public metadata with disposable in-memory test keys only.
Run after the .NET tests export fixtures under build/tuf-interop.
"""

import hashlib
import json
from pathlib import Path
import sys

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata


def main(directory: Path) -> None:
    directory = directory.resolve(strict=True)
    if "build" not in directory.parts:
        raise ValueError("Use an isolated build fixture directory")
    roles = ("root", "targets", "snapshot", "timestamp")
    wire = {role: (directory / f"{role}.json").read_bytes() for role in roles}
    metadata = {role: Metadata.from_bytes(data) for role, data in wire.items()}
    root = metadata["root"].signed
    for role, item in metadata.items():
        root.verify_delegate(role, item.signed_bytes, item.signatures)
    metadata["snapshot"].signed.meta["targets.json"].verify_length_and_hashes(wire["targets"])
    metadata["timestamp"].signed.snapshot_meta.verify_length_and_hashes(wire["snapshot"])
    print("python-tuf verified all .NET role signatures and metadata bindings")

    # Produce independently signed metadata for the reverse .NET verifier check.
    # No private key is written to disk or copied from an operator key store.
    names = ("root-1", "root-2", "root-3", "targets", "snapshot", "timestamp")
    signers = {name: CryptoSigner.generate_ecdsa() for name in names}
    documents = {role: json.loads(data) for role, data in wire.items()}
    root_document = documents["root"]["signed"]
    root_document["keys"] = {key.public_key.keyid: key.public_key.to_dict() for key in signers.values()}
    for role in roles:
        keys = ("root-1", "root-2", "root-3") if role == "root" else (role,)
        root_document["roles"][role]["keyids"] = [signers[name].public_key.keyid for name in keys]

    output = directory / "reference"
    output.mkdir(exist_ok=True)
    approved: dict[str, bytes] = {}
    for role in roles:
        document = documents[role]
        document["signatures"] = []
        if role in ("snapshot", "timestamp"):
            child = "targets" if role == "snapshot" else "snapshot"
            document["signed"]["meta"][f"{child}.json"].update(
                length=len(approved[child]),
                hashes={"sha256": hashlib.sha256(approved[child]).hexdigest()},
            )
        item = Metadata.from_dict(document)
        if role == "root":
            item.sign(signers["root-1"])
            item.sign(signers["root-2"], append=True)
        else:
            item.sign(signers[role])
        approved[role] = item.to_bytes()
        (output / f"{role}.json").write_bytes(approved[role])
    print("Wrote public python-tuf fixtures for independent .NET verification")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
