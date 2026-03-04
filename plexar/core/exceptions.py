"""
Plexar exception hierarchy.

All exceptions are subclasses of PlexarError, making it easy to
catch all library errors in one except clause if needed.
"""


class PlexarError(Exception):
    """Base exception for all Plexar errors."""


# ── Connection ──────────────────────────────────────────────────────

class ConnectionError(PlexarError):
    """Failed to establish a connection to a device."""


class AuthenticationError(ConnectionError):
    """Credentials were rejected by the device."""


class ConnectionTimeoutError(ConnectionError):
    """Connection attempt timed out."""


class ConnectionPoolExhaustedError(ConnectionError):
    """No available connections in the pool."""


# ── Transport ───────────────────────────────────────────────────────

class TransportError(PlexarError):
    """Low-level transport protocol error."""


class CommandError(TransportError):
    """Device returned an error response to a command."""


class CommandTimeoutError(TransportError):
    """Command execution timed out."""


class UnsupportedTransportError(TransportError):
    """The requested transport is not supported by this driver."""


# ── Driver ──────────────────────────────────────────────────────────

class DriverError(PlexarError):
    """Error originating from a vendor driver."""


class DriverNotFoundError(DriverError):
    """No driver registered for the given platform."""


class UnsupportedOperationError(DriverError):
    """The driver does not support this operation."""


# ── Parsing ─────────────────────────────────────────────────────────

class ParseError(PlexarError):
    """Failed to parse device output into a structured model."""


class TemplateNotFoundError(ParseError):
    """No parser template found for this command + platform combination."""


# ── Config ──────────────────────────────────────────────────────────

class ConfigError(PlexarError):
    """Error during config generation, push, or validation."""


class VerificationError(ConfigError):
    """Post-push verification checks failed."""


class RollbackError(ConfigError):
    """Config rollback failed — device may be in inconsistent state."""


class TransactionError(ConfigError):
    """Error within a config transaction."""


# ── Inventory ───────────────────────────────────────────────────────

class InventoryError(PlexarError):
    """Error loading or querying inventory."""


class DeviceNotFoundError(InventoryError):
    """No device matching the given filter exists in inventory."""


# ── Intent ──────────────────────────────────────────────────────────

class IntentError(PlexarError):
    """Error compiling or applying intent."""


class IntentCompilationError(IntentError):
    """Intent could not be compiled to device config."""


class IntentVerificationError(IntentError):
    """Applied intent could not be verified against running state."""


# ── Credentials ─────────────────────────────────────────────────────

class CredentialError(PlexarError):
    """Error resolving or accessing credentials."""


class MissingCredentialError(CredentialError):
    """A required credential field is missing or not resolvable."""
