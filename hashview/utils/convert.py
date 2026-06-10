"""Server-side conversion of raw source files into hashcat-ready text files."""


class ConversionError(Exception):
    """Raised when an external conversion tool fails or produces no output."""
