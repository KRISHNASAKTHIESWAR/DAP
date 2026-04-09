"""
test_anonymizer.py
──────────────────
Pytest suite for the Secure Data Anonymization Pipeline.

Covers:
  • Cryptographic consistency   - deterministic output for identical inputs.
  • Salt effectiveness          - different salts produce different digests.
  • Null / NaN safety           - graceful handling of missing values.
  • Pipeline integration        - end-to-end CSV transformation.
  • Environment guard           - missing HASH_SALT raises EnvironmentError.
"""

import os

import pandas as pd
import pytest

from anonymizer import generate_salted_hash, process_pipeline


# ─── Fixtures ────────────────────────────────────────────────────────────────

SALT_A = "salt_alpha_2026"
SALT_B = "salt_beta_9999"
SAMPLE_EMAIL = "test.test@mail.com"


# ─── Test 1: Hashing Consistency ─────────────────────────────────────────────

class TestHashingConsistency:
    """SHA-256 must be deterministic: identical inputs always yield identical output."""

    def test_hashing_consistency(self):
        """Hashing the same email with the same salt twice returns the exact same digest."""
        first_hash = generate_salted_hash(SAMPLE_EMAIL, SALT_A)
        second_hash = generate_salted_hash(SAMPLE_EMAIL, SALT_A)

        assert first_hash == second_hash, (
            "Expected identical hashes for identical (text, salt) inputs, "
            f"but got:\n  first : {first_hash}\n  second: {second_hash}"
        )

    def test_hash_is_sha256_length(self):
        """SHA-256 hex digests must always be exactly 64 characters long."""
        digest = generate_salted_hash(SAMPLE_EMAIL, SALT_A)
        assert isinstance(digest, str), "Hash result must be a string."
        assert len(digest) == 64, f"Expected 64-char hex digest, got {len(digest)} chars."

    def test_hash_is_hex(self):
        """The returned digest must contain only valid hexadecimal characters."""
        digest = generate_salted_hash(SAMPLE_EMAIL, SALT_A)
        assert all(c in "0123456789abcdef" for c in digest), (
            f"Hash contains non-hex characters: {digest}"
        )


# ─── Test 2: Salting Effectiveness ───────────────────────────────────────────

class TestSaltingEffectiveness:
    """Different salts must produce entirely different digests (avalanche effect)."""

    def test_salting_effectiveness(self):
        """Hashing the same email with two different salts produces different hashes."""
        hash_with_salt_a = generate_salted_hash(SAMPLE_EMAIL, SALT_A)
        hash_with_salt_b = generate_salted_hash(SAMPLE_EMAIL, SALT_B)

        assert hash_with_salt_a != hash_with_salt_b, (
            "Expected different hashes for different salts, "
            "but both produced the same digest. "
            "This would make the salt ineffective as a security measure."
        )

    def test_different_emails_same_salt_differ(self):
        """Two distinct emails hashed with the same salt must not collide."""
        hash_a = generate_salted_hash("test.test@mail.com", SALT_A)
        hash_b = generate_salted_hash("test2.test2@mail.com", SALT_A)

        assert hash_a != hash_b, (
            "Hash collision detected between different email addresses."
        )


# ─── Test 3: Null / NaN Value Handling ───────────────────────────────────────

class TestHandlesNullValues:
    """The hashing function must never raise an exception for missing values."""

    def test_handles_none(self):
        """Passing None must return pd.NA without raising any exception."""
        result = generate_salted_hash(None, SALT_A)
        assert pd.isna(result), f"Expected pd.NA for None input, got: {result!r}"

    def test_handles_pandas_na(self):
        """Passing pd.NA must return pd.NA without raising any exception."""
        result = generate_salted_hash(pd.NA, SALT_A)
        assert pd.isna(result), f"Expected pd.NA for pd.NA input, got: {result!r}"

    def test_handles_float_nan(self):
        """Passing float('nan') (as read from CSV) must return pd.NA gracefully."""
        result = generate_salted_hash(float("nan"), SALT_A)
        assert pd.isna(result), f"Expected pd.NA for NaN input, got: {result!r}"

    def test_null_does_not_raise(self):
        """No exception of any kind must be raised for any null-like input."""
        null_inputs = [None, pd.NA, float("nan")]
        for null_val in null_inputs:
            try:
                generate_salted_hash(null_val, SALT_A)
            except Exception as exc:  # noqa: BLE001
                pytest.fail(
                    f"generate_salted_hash raised {type(exc).__name__} for "
                    f"input {null_val!r}: {exc}"
                )


# ─── Test 4: Pipeline Integration ────────────────────────────────────────────

class TestPipelineIntegration:
    """End-to-end smoke tests for process_pipeline()."""

    def test_pipeline_creates_output_file(self, tmp_path, monkeypatch):
        """process_pipeline() must create the output CSV file."""
        monkeypatch.setenv("HASH_SALT", SALT_A)

        # Build a minimal input CSV
        input_csv = tmp_path / "raw_data.csv"
        input_csv.write_text(
            "user_id,name,email,department,last_login\n"
            "U001,A,a@test.com,Eng,2026-01-01\n"
        )
        output_csv = tmp_path / "secured_data.csv"

        process_pipeline(str(input_csv), str(output_csv))

        assert output_csv.exists(), "Output CSV was not created by process_pipeline()."

    def test_pipeline_redacts_name(self, tmp_path, monkeypatch):
        """All values in the 'name' column must equal '[REDACTED]' after the pipeline."""
        monkeypatch.setenv("HASH_SALT", SALT_A)

        input_csv = tmp_path / "raw_data.csv"
        input_csv.write_text(
            "user_id,name,email,department,last_login\n"
            "U001,A,a@test.com,Eng,2026-01-01\n"
            "U002,B,b@test.com,QA,2026-01-02\n"
        )
        output_csv = tmp_path / "secured_data.csv"
        process_pipeline(str(input_csv), str(output_csv))

        df = pd.read_csv(output_csv)
        assert all(df["name"] == "[REDACTED]"), (
            f"'name' column still contains PII: {df['name'].tolist()}"
        )

    def test_pipeline_hashes_email(self, tmp_path, monkeypatch):
        """The 'email' column must not contain the original plaintext after the pipeline."""
        monkeypatch.setenv("HASH_SALT", SALT_A)
        original_email = "a@test.com"

        input_csv = tmp_path / "raw_data.csv"
        input_csv.write_text(
            f"user_id,name,email,department,last_login\n"
            f"U001,A,{original_email},Eng,2026-01-01\n"
        )
        output_csv = tmp_path / "secured_data.csv"
        process_pipeline(str(input_csv), str(output_csv))

        df = pd.read_csv(output_csv)
        assert original_email not in df["email"].values, (
            "Original plaintext email found in output - hashing did not occur."
        )


# ─── Test 5: Environment Guard ────────────────────────────────────────────────

class TestEnvironmentGuard:
    """process_pipeline() must fail fast when HASH_SALT is absent."""

    def test_missing_salt_raises_environment_error(self, tmp_path, monkeypatch):
        """An EnvironmentError must be raised if HASH_SALT is not set."""
        monkeypatch.delenv("HASH_SALT", raising=False)

        # Also ensure no .env file can be loaded during this test
        monkeypatch.chdir(tmp_path)

        input_csv = tmp_path / "raw_data.csv"
        input_csv.write_text(
            "user_id,name,email,department,last_login\n"
            "U001,A,a@test.com,Eng,2026-01-01\n"
        )
        output_csv = tmp_path / "secured_data.csv"

        with pytest.raises(EnvironmentError, match="HASH_SALT"):
            process_pipeline(str(input_csv), str(output_csv))
