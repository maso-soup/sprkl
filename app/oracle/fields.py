"""The fields of a finding the running app is allowed to know about.

A leaf module with no imports on purpose: tools/strip_catalog.py loads this file
directly, by path, so generating the image's catalog does not drag in Flask and
the rest of the app. app/oracle/catalog.py re-exports it.
"""

# The oracle API serves exactly these; nothing else in app/ reads any other field.
# Adding one here carries it into the stripped runtime catalog automatically.
RUNTIME_FIELDS = ("id", "title", "family", "category", "skill",
                  "owasp_web", "owasp_api", "cwe", "difficulty",
                  "tier", "status")
