"""
Password hashing with Argon2id.

Argon2id is the recommended password hashing algorithm because:
- Memory-hard (resists GPU/ASIC attacks)
- Side-channel resistant (id variant)
- Winner of the Password Hashing Competition

Security parameters are tuned for:
- ~250ms hash time on modern hardware
- 64MB memory usage
- Good resistance to parallel attacks
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import secrets
import string

# Configure Argon2id with secure parameters
# These settings provide good security while being usable on modest hardware
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB memory usage
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of the hash in bytes
    salt_len=16,        # Length of the random salt
)


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.
    
    Args:
        password: The plaintext password to hash
    
    Returns:
        The hashed password string (includes algorithm, params, salt, and hash)
    """
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: The plaintext password to verify
        password_hash: The stored hash to verify against
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        # Hash is malformed - treat as verification failure
        return False


def needs_rehash(password_hash: str) -> bool:
    """
    Check if a password hash needs to be rehashed.
    
    This is useful when upgrading security parameters over time.
    After a successful login, check this and rehash if needed.
    
    Args:
        password_hash: The stored hash to check
    
    Returns:
        True if hash should be regenerated with current parameters
    """
    try:
        return ph.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True  # Invalid hash should definitely be rehashed


def generate_temp_password(length: int = 16) -> str:
    """
    Generate a secure temporary password.
    
    Used for:
    - Initial user account creation
    - Password reset
    
    Args:
        length: Length of the password (minimum 12)
    
    Returns:
        A random password meeting complexity requirements
    """
    if length < 12:
        length = 12
    
    # Ensure at least one of each required character type
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    
    # Fill the rest with random characters
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password.extend(secrets.choice(alphabet) for _ in range(length - 4))
    
    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password meets minimum security requirements.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    
    Args:
        password: The password to validate
    
    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []
    
    if len(password) < 12:
        issues.append("Password must be at least 12 characters long")
    
    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one digit")
    
    special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
    if not any(c in special_chars for c in password):
        issues.append("Password must contain at least one special character")
    
    # Check for common passwords (basic check)
    common_passwords = {
        "password123!", "admin123!", "letmein123!", "welcome123!",
        "Password123!", "Admin123!", "Letmein123!", "Welcome123!",
    }
    if password.lower() in {p.lower() for p in common_passwords}:
        issues.append("Password is too common")
    
    return len(issues) == 0, issues

