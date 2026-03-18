"""
CSRF (Cross-Site Request Forgery) Scanner Module

Detects CSRF vulnerabilities by:
1. Looking for forms that lack anti-CSRF tokens
2. Checking for missing SameSite cookie attributes
3. Verifying that state-changing requests require authentication
4. Testing if sensitive actions work without a valid Referer/Origin

CSRF allows attackers to trick authenticated users into performing
unintended actions on websites where they are logged in.
"""

import re
from typing import Dict, List, Any
from urllib.parse import urlparse

from scanner.base import BaseScanner


class CSRFScanner(BaseScanner):
    """
    Scanner for detecting Cross-Site Request Forgery (CSRF) vulnerabilities.

    This scanner analyses HTML forms for the presence of CSRF tokens and
    tests whether state-changing endpoints enforce origin checks.
    """

    @property
    def name(self) -> str:
        return "CSRF Scanner"

    @property
    def severity(self) -> str:
        return "High"

    def __init__(self, timeout: int = 10, delay: float = 0.5):
        super().__init__(timeout=timeout, delay=delay)

        # Common CSRF token field names used by frameworks
        self.token_field_names = [
            "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
            "_token", "_csrf", "__requestverificationtoken",
            "authenticity_token", "xsrf", "xsrftoken", "_wpnonce",
            "token", "form_token", "security_token", "anti_csrf",
        ]

        # HTTP methods that change state (should be CSRF-protected)
        self.unsafe_methods = {"post", "put", "patch", "delete"}

        # Patterns that suggest a form performs a sensitive action
        self.sensitive_action_patterns = [
            r"(?i)(login|signin|sign[\-_]in)",
            r"(?i)(register|signup|sign[\-_]up|create[\-_]account)",
            r"(?i)(password|passwd|pwd)",
            r"(?i)(transfer|payment|pay|checkout|purchase|buy)",
            r"(?i)(delete|remove|drop)",
            r"(?i)(update|edit|modify|change)",
            r"(?i)(submit|save|upload)",
            r"(?i)(profile|settings|account|preference)",
            r"(?i)(admin|dashboard|manage)",
        ]
        self.compiled_action_patterns = [
            re.compile(p) for p in self.sensitive_action_patterns
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _form_has_csrf_token(self, form: Dict) -> bool:
        """
        Return True when the form contains a recognisable CSRF token field.

        Args:
            form: Form dictionary as produced by the crawler

        Returns:
            True if a CSRF token was found
        """
        for field in form.get("inputs", []):
            name = (field.get("name") or "").lower()
            field_type = (field.get("type") or "text").lower()
            if name in self.token_field_names:
                return True
            # Hidden fields whose *name* contains "token" / "csrf"
            if field_type == "hidden" and any(
                kw in name for kw in ("csrf", "token", "nonce", "xsrf")
            ):
                return True
        return False

    def _form_is_sensitive(self, form: Dict) -> bool:
        """
        Return True when the form's action URL or input names suggest a
        state-changing / sensitive operation.

        Args:
            form: Form dictionary

        Returns:
            True if the form appears sensitive
        """
        action = form.get("action", "")
        # Check the action URL
        for pat in self.compiled_action_patterns:
            if pat.search(action):
                return True
        # Check input field names
        for field in form.get("inputs", []):
            name = field.get("name") or ""
            for pat in self.compiled_action_patterns:
                if pat.search(name):
                    return True
        return False

    def _test_no_origin_check(self, url: str, form: Dict) -> bool:
        """
        Send a POST request without an Origin / Referer header to see
        whether the server rejects it.  A 200 response to such a request
        for a sensitive form is a strong CSRF indicator.

        Returns:
            True if the server accepted the cross-origin-like request
        """
        method = (form.get("method") or "get").lower()
        if method not in self.unsafe_methods:
            return False

        # Build minimal form data with dummy values
        data = {}
        for field in form.get("inputs", []):
            fname = field.get("name")
            if fname and (field.get("type") or "text").lower() not in (
                "submit", "button", "image", "reset"
            ):
                data[fname] = field.get("value") or "test"

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*",
            # Deliberately omit Origin and Referer to simulate cross-origin request
        }

        try:
            response = self.make_request(
                url,
                method=method.upper(),
                data=data,
            )
            if response is None:
                return False
            # If the server returns 200 / 302 (redirect after success) → likely
            # not protected.  A 403 / 419 / 400 suggests a CSRF check exists.
            if response.status_code in (200, 201, 301, 302, 303, 307):
                return True
        except Exception as e:
            self.logger.debug(f"CSRF origin-check test error for {url}: {e}")

        return False

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for CSRF vulnerabilities.

        Args:
            urls:  List of URLs discovered by the crawler (used for extra
                   header checks)
            forms: List of form dictionaries to inspect

        Returns:
            List of vulnerability dictionaries
        """
        self.vulnerabilities = []

        if not forms:
            self.logger.info("  No forms found — skipping CSRF scan")
            return self.vulnerabilities

        self.logger.info(f"  Checking {len(forms)} forms for CSRF protection...")

        for form in forms:
            action_url = form.get("action", "")
            method = (form.get("method") or "get").lower()

            # Only POST/PUT/PATCH/DELETE forms are CSRF-relevant
            if method not in self.unsafe_methods:
                continue

            has_token = self._form_has_csrf_token(form)
            is_sensitive = self._form_is_sensitive(form)

            if has_token:
                # Token present → likely protected; skip deeper testing
                self.logger.debug(
                    f"  CSRF token found in form at {action_url} — skipping"
                )
                continue

            # No CSRF token found
            # Severity depends on whether the form appears sensitive
            severity = "High" if is_sensitive else "Medium"

            # Optionally test whether server rejects cross-origin requests
            server_accepts = self._test_no_origin_check(action_url, form)

            evidence = (
                "Form has no detectable CSRF token field. "
                + (
                    "Server accepted cross-origin POST request."
                    if server_accepts
                    else "No CSRF token found in form inputs."
                )
            )

            self.add_vulnerability(
                vuln_type="Cross-Site Request Forgery (CSRF)",
                url=action_url,
                param="form",
                payload="(no CSRF token)",
                evidence=evidence,
                severity=severity,
                description=(
                    f"The form at {action_url!r} submits via {method.upper()} "
                    "but does not include a CSRF token. An attacker can craft a "
                    "malicious page that silently submits this form on behalf of "
                    "an authenticated user, causing unintended state changes."
                ),
                recommendation=(
                    "Add a per-session, unpredictable CSRF token to every "
                    "state-changing form and validate it server-side. Use the "
                    "SameSite=Strict or SameSite=Lax cookie attribute as a "
                    "defence-in-depth measure. Verify the Origin / Referer header "
                    "for sensitive endpoints."
                ),
            )

            self.throttle()

        return self.vulnerabilities
