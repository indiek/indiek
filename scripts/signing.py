import json
import hashlib
import nacl.signing
from pydantic import BaseModel

# import nacl.encoding


def get_signing_key(hex_private_key):
    """
    Loads an existing Ed25519 private key from a hex string.
    """
    # 1. Convert hex string to bytes
    private_key_bytes = bytes.fromhex(hex_private_key)

    # 2. Validate length (Ed25519 seed must be exactly 32 bytes)
    if len(private_key_bytes) != 32:
        raise ValueError("Invalid key length. Ed25519 private key must be 32 bytes.")

    return nacl.signing.SigningKey(private_key_bytes)


# 2. Canonical Hashing
def get_canonical_hash(body: dict | BaseModel) -> bytes:
    if isinstance(body, BaseModel):
        # 1. Dump to a standard, JSON-safe dictionary
        json_ready_dict = body.model_dump(mode="json")
    else:
        json_ready_dict = body

    # Sort keys alphabetically to ensure deterministic hashing
    json_dump = json.dumps(json_ready_dict, sort_keys=True)

    body_bytes = json_dump.encode("utf-8")
    return hashlib.sha256(body_bytes).digest()


# 3. Signing Function
def sign_event(body: dict | BaseModel, signing_key):
    # Hash the data
    msg_hash = get_canonical_hash(body)

    # Sign the hash
    signed_message = signing_key.sign(msg_hash)

    # Extract only the signature and convert to hex for JSON storage
    return signed_message.signature.hex()


# 4. Verification Function (Crucial for your Archive)
def verify_signature(body, signature_hex, public_key_hex):
    try:
        # Reconstruct public key
        verify_key = nacl.signing.VerifyKey(
            public_key_hex, encoder=nacl.encoding.HexEncoder
        )

        # Verify the signature against the hash
        msg_hash = get_canonical_hash(body)
        verify_key.verify(msg_hash, bytes.fromhex(signature_hex))
        return True
    except (nacl.exceptions.BadSignatureError, ValueError):
        return False
