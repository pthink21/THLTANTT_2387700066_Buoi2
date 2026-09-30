"""
Secure password hashing utilities using Argon2id.

Argon2id is the variant recommended by the Password Hashing
Symposium (PHC) and provides resistance against both GPU and
side-channel attacks.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# A single reusable hasher with sensible defaults.
_ph = PasswordHasher(
    time_cost=3,       # number of iterations
    memory_cost=65536, # 64 MiB
    parallelism=4,     # 4 threads
    hash_len=32,       # 256-bit hash
    salt_len=16,       # 128-bit salt
)


def hash_password_secure(password: str) -> str:
    """
    Hash a password using Argon2id.

    The returned string encodes all parameters (algorithm, time cost,
    memory cost, parallelism, salt, hash) and is self-describing.

    Args:
        password: Plaintext password.

    Returns:
        Argon2 encoded hash string (e.g. ``$argon2id$v=19$m=65536,t=3,p=4$...``).
    """
    return _ph.hash(password)


def verify_password_hash(password_hash: str, password: str) -> bool:
    """
    Verify a password against an Argon2 hash.

    Args:
        password_hash: Encoded hash from :func:`hash_password_secure`.
        password:      Plaintext password to check.

    Returns:
        ``True`` if the password matches, ``False`` otherwise.
    """
    try:
        _ph.verify(password_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
