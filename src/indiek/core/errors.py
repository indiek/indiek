"""Copyright 2026 Adrian Ernesto Radillo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

Exception hierarchy of the IndieK SDK."""


class IndieKError(Exception):
    """Base class of every error raised by the IndieK SDK."""


class IntegrityError(IndieKError):
    """The archive on disk is corrupted, tampered with or inconsistent."""


class UnknownItemError(IndieKError, ValueError):
    """An ID or alias does not resolve to an item of the expected kind."""


class AuthorshipError(IndieKError, ValueError):
    """The current author is not allowed to perform the operation."""


class ArchiveRuleError(IndieKError, ValueError):
    """The requested write would violate a rule of the archive format."""


class ArchiveLockedError(IndieKError):
    """Another process holds the archive's write lock (``<archive>/.ik.lock``)
    for longer than the writer's ``lock_timeout``."""


class KeychainError(IndieKError):
    """The OS keychain refused an operation on the IndieK author key."""


class KeychainUnavailableError(KeychainError):
    """No usable OS keychain (none installed, locked, or the ``keyring``
    package is missing); use ``IK_AUTHOR_PRIVATE_KEY`` instead."""
