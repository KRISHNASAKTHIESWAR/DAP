"""
anonymizer.py
─────────────
Secure Data Anonymization Pipeline – Core Engine.

Responsibilities:
  • Load configuration from environment variables (never from hard-coded values).
  • Hash PII fields (email) with a salted SHA-256 digest.
  • Redact free-text PII fields (name) unconditionally.
  • Emit structured audit log entries at every significant pipeline step.
"""

import hashlib
import logging
import os
import sys

import pandas as pd
from dotenv import load_dotenv

# ─── Logging Configuration ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ─── Cryptographic Helper ─────────────────────────────────────────────────────

def generate_salted_hash(text: object, salt: str) -> object:
    """Return a SHA-256 hex digest of ``salt + text``.

    Gracefully handles missing / null values:
      • If *text* is ``None``, ``float('nan')``, or any Pandas NA-like value,
        the function returns ``pd.NA`` without raising an exception.

    Args:
        text:  The plaintext value to hash (expected: str).
        salt:  The secret salt string loaded from the environment.

    Returns:
        A 64-character hex string, or ``pd.NA`` for null inputs.
    """
    # Guard: treat None / NaN / pd.NA as missing
    try:
        if text is None or pd.isna(text):
            logger.warning("Null value encountered during hashing – returning pd.NA.")
            return pd.NA
    except (TypeError, ValueError):
        # pd.isna() can raise on certain non-scalar objects; treat as non-null
        pass

    payload = salt + str(text)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest


# ─── Pipeline Orchestrator ────────────────────────────────────────────────────

def process_pipeline(input_file: str, output_file: str) -> None:
    """Execute the full anonymization pipeline.

    Steps:
      1. Load and validate the ``HASH_SALT`` environment variable.
      2. Read *input_file* into a Pandas DataFrame.
      3. Apply salted SHA-256 hashing to the ``email`` column.
      4. Redact the ``name`` column (replace every value with ``[REDACTED]``).
      5. Write the secured DataFrame to *output_file*.

    Args:
        input_file:  Path to the raw CSV file.
        output_file: Destination path for the anonymized CSV.

    Raises:
        EnvironmentError: If ``HASH_SALT`` is not set in the environment.
        FileNotFoundError: If *input_file* does not exist.
    """
    logger.info("Pipeline starting. Input: '%s' | Output: '%s'", input_file, output_file)

    # ── Step 1: Load & validate environment ──────────────────────────────────
    load_dotenv()
    salt = os.getenv("HASH_SALT")

    if not salt:
        logger.error("HASH_SALT environment variable is missing or empty – aborting.")
        raise EnvironmentError(
            "HASH_SALT must be set in the environment or a .env file. "
            "Never hard-code cryptographic secrets in source code."
        )

    logger.info("HASH_SALT loaded successfully (value masked for security).")

    # ── Step 2: Load CSV ──────────────────────────────────────────────────────
    logger.info("Loading input data from '%s'.", input_file)
    df = pd.read_csv(input_file)
    logger.info("Loaded %d rows and %d columns.", len(df), len(df.columns))

    # ── Step 3: Hash the email column ─────────────────────────────────────────
    logger.info("Applying salted SHA-256 hash to 'email' column.")
    df["email"] = df["email"].apply(lambda val: generate_salted_hash(val, salt))
    logger.info("'email' column hashed successfully.")

    # ── Step 4: Redact the name column ────────────────────────────────────────
    logger.info("Redacting 'name' column.")
    df["name"] = "[REDACTED]"
    logger.info("'name' column redacted successfully.")

    # ── Step 5: Export secured data ───────────────────────────────────────────
    logger.info("Writing secured data to '%s'.", output_file)
    df.to_csv(output_file, index=False)
    logger.info(
        "Pipeline complete. %d rows written to '%s'. Audit trail complete.",
        len(df),
        output_file,
    )


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    process_pipeline(
        input_file="raw_data.csv",
        output_file="secured_data.csv",
    )
