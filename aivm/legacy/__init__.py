"""Versioned backwards-compatibility implementations.

Compatibility code is intentionally grouped by the newest release boundary it
supports. Ordinary runtime modules should import a versioned implementation
explicitly so compatibility dependencies are visible and removable.
"""
