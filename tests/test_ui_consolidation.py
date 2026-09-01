"""UI consolidation pass: one RewindSec product UI, legacy simulator gone.

Covers:
  * the shared design system is used everywhere (no ``base_stub``/``styles.css``
    survivors, no onion/dark-market copy on the landing page);
  * every retained route renders without ``TemplateNotFound`` or a 500 on a
    fresh checkout;
  * every legacy route removed by this pass now 404s (or 405s for POST-only
    ones hit with GET);
  * no retained template still links to a removed legacy route;
  * the study participant flow never links to /training, /resources,
    /dashboard or /instructor/login, while still using the shared stylesheet.
"""

import glob
import os
import re

import pytest

from conftest import csrf_for, login_instructor

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATES_DIR = os.path.join(REPO_ROOT, "templates")


def all_template_sources():
    for path in glob.glob(os.path.join(TEMPLATES_DIR, "*.html")):
        with open(path, encoding="utf-8") as handle:
            yield os.path.basename(path), handle.read()


# -- the legacy stylesheet/base and its templates are gone -------------------

def test_base_stub_template_is_gone():
    assert not os.path.exists(os.path.join(TEMPLATES_DIR, "base_stub.html"))


def test_legacy_stylesheet_is_gone():
    assert not os.path.exists(os.path.join(REPO_ROOT, "static", "styles.css"))


@pytest.mark.parametrize("name", [
    "marketplace.html", "page.html", "product.html", "phishing_consent.html",
    "phishing_login.html", "phishing_portal.html", "phishing_result.html",
    "ransomware_menu.html", "hacking_tools.html", "ransomware_download.html",
    "file_browser.html", "ransomware_screen.html", "ransomware_education.html",
])
def test_legacy_templates_are_gone(name):
    assert not os.path.exists(os.path.join(TEMPLATES_DIR, name))


def test_no_retained_template_references_base_stub_or_legacy_stylesheet():
    for name, source in all_template_sources():
        assert "base_stub" not in source, name
        assert "styles.css" not in source, name


LEGACY_LINK_PATTERNS = [
    "/marketplace/", "/ransomware/menu", "/ransomware/trigger",
    "/ransomware/activate", "/ransomware/screen", "/ransomware/reveal",
    "/ransomware/simulate", "/ransomware/restore", "/download/tool",
    "/files/browser", "/product/", "/page/", "/phishing/consent",
    "/phishing/login", "/phishing/portal", "/phishing/debrief", "/payment/",
]


def test_no_retained_template_links_to_a_removed_legacy_route():
    for name, source in all_template_sources():
        for pattern in LEGACY_LINK_PATTERNS:
            assert pattern not in source, "%s still references %s" % (name, pattern)


# -- the landing page -----------------------------------------------------

def test_landing_page_is_the_rewindsec_product_ui(client):
    page = client.get("/")
    assert page.status_code == 200
    body = page.data.decode()
    assert "Deterministic counterfactual" in body
    assert "rewindsec.css" in body
    lowered = body.lower()
    for banned in ("onion", "dark web", "dark-web", "marketplace", ".onion"):
        assert banned not in lowered


# -- shared stylesheet everywhere --------------------------------------------

RENDER_CHECKS = [
    ("/", "get", 200),
    ("/training", "get", 200),
    ("/training/phishing", "get", 200),
    ("/training/ransomware", "get", 200),
    ("/training/mfa", "get", 200) ,
    ("/training/bec", "get", 200),
    ("/resources", "get", 200),
    ("/instructor/login", "get", 200),
]


@pytest.mark.parametrize("path,method,expected", RENDER_CHECKS)
def test_public_routes_render_with_the_shared_stylesheet(client, path, method,
                                                          expected):
    response = getattr(client, method)(path)
    if response.status_code != expected:
        # A couple of module entry points may redirect to their brief/home
        # page rather than rendering directly; follow once.
        response = getattr(client, method)(path, follow_redirects=True)
    assert response.status_code == expected
    assert b"rewindsec.css" in response.data


def test_instructor_pages_render_with_the_shared_stylesheet(instructor):
    for path in ("/dashboard",):
        page = instructor.get(path)
        assert page.status_code == 200
        assert b"rewindsec.css" in page.data


def test_study_admin_renders_with_the_shared_stylesheet_when_enabled(
        flask_app, instructor):
    """/study/* 404s unless research mode is on (fail-closed by design, see
    study_routes.py's ``_gate``); flip it on for this app only for the
    duration of the check."""
    original = {key: flask_app.config.get(key) for key in (
        "STUDY_ENABLED", "STUDY_ASSIGNMENT_SECRET", "STUDY_ACCESS_CODE",
        "STUDY_CONTINUITY_SECRET")}
    flask_app.config.update(
        STUDY_ENABLED=True, STUDY_ASSIGNMENT_SECRET="test-assign-secret",
        STUDY_ACCESS_CODE="test-access-code",
        STUDY_CONTINUITY_SECRET="test-continuity-secret")
    try:
        page = instructor.get("/study/admin")
        assert page.status_code == 200
        assert b"rewindsec.css" in page.data
    finally:
        flask_app.config.update(original)


def test_404_page_uses_the_shared_stylesheet(client):
    page = client.get("/this-route-does-not-exist")
    assert page.status_code == 404
    assert b"rewindsec.css" in page.data
    assert b"Page not found" in page.data


# -- removed legacy routes are actually gone ---------------------------------

REMOVED_GET_ROUTES = [
    "/marketplace/plants", "/marketplace/weapons", "/marketplace/tools",
    "/ransomware/menu", "/ransomware/screen", "/files/browser",
    "/download/tool/1", "/product/1", "/page/exotic-plants",
    "/phishing/consent", "/phishing/login", "/phishing/portal",
    "/phishing/debrief", "/payment/1", "/deets",
]

REMOVED_POST_ROUTES = [
    "/ransomware/trigger", "/ransomware/activate", "/ransomware/reveal",
    "/ransomware/simulate", "/ransomware/restore",
]


@pytest.mark.parametrize("path", REMOVED_GET_ROUTES)
def test_removed_legacy_get_routes_404(client, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", REMOVED_POST_ROUTES)
def test_removed_legacy_post_routes_are_unreachable(client, path):
    # Either 404 (route gone) or 405 (path reused by nothing, method not
    # allowed) -- never a 200, and never a redirect into working behaviour.
    response = client.post(path, data={"csrf_token": csrf_for(client)})
    assert response.status_code in (404, 405)


# -- study participant flow never reveals ordinary product nav --------------

STUDY_NAV_FORBIDDEN = ("/training\"", "/training'", ">Training<",
                       "/resources\"", ">Resources<",
                       "/dashboard\"", ">Instructor console<",
                       "/instructor/login\"", ">Instructor<")


def test_study_pages_use_shared_styling_and_no_ordinary_nav(flask_app, client):
    """The study gate page, with research mode switched on for this check
    only (see ``test_study_admin_renders_with_the_shared_stylesheet_when_enabled``
    for why: /study/* fail-closed 404s otherwise)."""
    original = {key: flask_app.config.get(key) for key in (
        "STUDY_ENABLED", "STUDY_ASSIGNMENT_SECRET", "STUDY_ACCESS_CODE",
        "STUDY_CONTINUITY_SECRET")}
    flask_app.config.update(
        STUDY_ENABLED=True, STUDY_ASSIGNMENT_SECRET="test-assign-secret",
        STUDY_ACCESS_CODE="test-access-code",
        STUDY_CONTINUITY_SECRET="test-continuity-secret")
    try:
        response = client.get("/study/")
        assert response.status_code == 200
        body = response.data.decode()
        assert b"rewindsec.css" in response.data
        for forbidden in STUDY_NAV_FORBIDDEN:
            assert forbidden not in body
    finally:
        flask_app.config.update(original)


def test_study_base_template_declares_no_nav_links():
    with open(os.path.join(TEMPLATES_DIR, "study_base.html"), encoding="utf-8") as handle:
        source = handle.read()
    # The nav block must be empty: no href at all in the override.
    block = re.search(r"{%\s*block nav\s*%}(.*?){%\s*endblock\s*%}", source, re.S)
    assert block is not None
    assert "href" not in block.group(1)


# -- instructor nav uses POST + CSRF for sign-out, not a GET link -----------

def test_instructor_sign_out_is_a_csrf_protected_post_form(instructor):
    page = instructor.get("/dashboard")
    body = page.data.decode()
    assert 'action="/instructor/logout"' in body
    assert 'method="post"' in body.lower()
    assert "csrf_token" in body
