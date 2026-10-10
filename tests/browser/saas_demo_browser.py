#!/usr/bin/env python3
"""Browser acceptance for the isolated SaaS fixture; no Core, secrets or API calls.

Run against an explicitly enabled LOCAL Vite dev server. Uses Chromium with
Playwright installed only in the GitHub Actions runner (no lockfile changes).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

BASE_URL = os.environ.get("SAAS_BROWSER_URL", "http://127.0.0.1:5173/#/saas-demo-preview")
OUTPUT = Path(os.environ.get("SAAS_BROWSER_ARTIFACTS", "tests/browser/artifacts"))
OUTPUT.mkdir(parents=True, exist_ok=True)

CASES = [
    ("desktop-ru-light", 1440, 900, "ru-RU", "light", "no-preference"),
    ("tablet-en-dark", 820, 1180, "en-US", "dark", "no-preference"),
    ("mobile-ru-dark-reduced", 390, 844, "ru-RU", "dark", "reduce"),
    ("small-mobile-en-light-reduced", 320, 720, "en-US", "light", "reduce"),
]


def ensure(condition: bool, description: str) -> None:
    if not condition:
        raise AssertionError(description)


def visible_text(page: Page) -> str:
    return page.locator("body").inner_text()


def assert_no_document_overflow(page: Page, label: str) -> None:
    metrics = page.evaluate("""() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
      viewport: window.innerWidth
    })""")
    ensure(metrics["scroll"] <= metrics["client"] + 2,
           f"{label}: document horizontal overflow: {metrics}")


def screenshot(page: Page, name: str) -> None:
    page.screenshot(path=str(OUTPUT / name), full_page=True,
                    animations="disabled", timeout=30000)


def check_tenants_search_wizard(page: Page, language: str) -> None:
    ru = language == "ru"
    tenant = page.locator("#saas-demo-tenant")
    tabs = page.get_by_role("tab")
    ensure(tabs.count() == 4, "Expected four accessible tab controls")

    # Keyboard navigation must update both selected state and keyboard focus.
    tabs.nth(0).focus()
    page.keyboard.press("End")
    ensure(tabs.nth(3).get_attribute("aria-selected") == "true",
           "End did not select the last tab")
    ensure(tabs.nth(3).evaluate("(el) => el === document.activeElement"),
           "End did not focus the last tab")
    page.keyboard.press("Home")
    ensure(tabs.nth(0).get_attribute("aria-selected") == "true",
           "Home did not select first tab")

    tabs.nth(1).click()
    text = visible_text(page)
    ensure("account-platform" in text and "account-north" in text,
           "North must see owned and explicitly granted account metadata")
    ensure("account-orbit" not in text, "North leaked Orbit account metadata")
    ensure("North Studio" in text, "North resource owner must be visible")
    ensure(("Платформа" if ru else "Platform") in text,
           "Explicit platform owner must be displayed")

    search = page.locator("#saas-demo-search")
    search.fill("account-orbit")
    ensure("account-platform" not in visible_text(page),
           "Search must filter the account list")
    search.fill("")
    ensure("account-platform" in visible_text(page), "Clear search failed")

    # The 4-step wizard is read-only; advancing cannot create anything.
    page.get_by_role("button", name=("Далее" if ru else "Next"), exact=True).click()
    ensure("2/4" in visible_text(page), "Wizard did not advance to step 2")
    page.get_by_role("button", name=("Далее" if ru else "Next"), exact=True).click()
    page.get_by_role("button", name=("Далее" if ru else "Next"), exact=True).click()
    ensure("4/4" in visible_text(page), "Wizard did not reach step 4")
    page.get_by_role("button", name=("Сначала" if ru else "Restart"), exact=True).click()
    ensure("1/4" in visible_text(page), "Wizard did not restart")

    # A tenant change must reset the tab/search and not display foreign metadata.
    search.fill("account-north")
    tenant.select_option("demo-orbit")
    ensure(tabs.nth(0).get_attribute("aria-selected") == "true",
           "Switching tenants must return to the first tab")
    tabs.nth(1).click()
    text = visible_text(page)
    ensure("account-orbit" in text, "Orbit account missing")
    ensure("account-north" not in text and "account-platform" not in text,
           "Tenant switch leaked North/platform account")
    ensure(page.locator("#saas-demo-search").input_value() == "",
           "Search was not reset on tenant change")

    tabs.nth(2).click()
    text = visible_text(page)
    ensure("vpn-orbit" not in text or "VPN connector" in text,
           "VPN fixture label not rendered as expected")
    ensure("EU SOCKS5" not in text and "Shared HTTPS" not in text,
           "Orbit network view leaked North/platform egress")
    tenant.select_option("demo-north")


def check_flow(page: Page, language: str) -> None:
    ru = language == "ru"
    page.get_by_role("tab").nth(3).click()
    selector = page.locator("#saas-demo-scenario")
    nodes = page.locator('button[aria-pressed]')
    ensure(nodes.count() == 7, "Flow must have seven keyboard-accessible nodes")

    selector.select_option("north-owned")
    ensure("account-north" in visible_text(page), "Allowed fixture missing selected account")
    nodes.nth(4).focus()
    page.keyboard.press("Space")
    ensure(nodes.nth(4).get_attribute("aria-pressed") == "true",
           "Space must select a flow node")
    inspector = page.get_by_role("region", name=("Выбранный этап" if ru else "Selected stage"))
    ensure("account-north" in inspector.inner_text(),
           "Flow inspector should show an owned and permitted reference")
    ensure("North Studio" in inspector.inner_text(), "Owned account owner is hidden")

    selector.select_option("north-shared")
    nodes.nth(4).click()
    text = inspector.inner_text()
    ensure("account-platform" in text, "Shared account ID should be shown when granted")
    ensure(("Платформа" if ru else "Platform") in text,
           "Shared account platform owner should be shown")

    selector.select_option("north-foreign-account")
    ensure(nodes.nth(4).get_attribute("aria-pressed") == "true",
           "Blocked account node must be auto-selected")
    ensure(("Заблокировано здесь" if ru else "Blocked here") in inspector.inner_text(),
           "Denial stage is not explained")
    ensure("account-orbit" not in visible_text(page) and "Orbit Lab" not in inspector.inner_text(),
           "Denied foreign account identity was exposed in route details")
    ensure(("Недоступно или нет разрешения" if ru else "Unavailable or not permitted") in inspector.inner_text(),
           "Unpermitted account must display a neutral label")

    selector.select_option("north-foreign-egress")
    nodes.nth(5).click()
    ensure("proxy-orbit" not in visible_text(page), "Denied foreign egress identity was exposed")

    selector.select_option("north-offline")
    ensure(nodes.nth(5).get_attribute("aria-pressed") == "true",
           "Offline egress must be auto-focused in the inspector")
    ensure("Offline proxy" in inspector.inner_text(), "Offline proxy should be explained")
    ensure(("Что делать" if ru else "Next step") in inspector.inner_text(),
           "Blocked egress must include a recovery action")
    ensure(("Не достигнуто" if ru else "Not reached") in visible_text(page),
           "Downstream AI provider cannot be marked reached after denial")

    selector.select_option("north-direct")
    ensure(nodes.nth(5).get_attribute("aria-pressed") == "true",
           "Unapproved direct route must stop at egress")

    # Network hops are schematic on ALLOW, never proof of a real request.
    selector.select_option("north-owned")
    nodes.nth(6).click()
    ensure(("Только схема" if ru else "Schematic only") in inspector.inner_text(),
           "AI provider must be explicitly schematic")
    nodes.nth(1).click()
    ensure(("Только схема" if ru else "Schematic only") in inspector.inner_text(),
           "Gateway must be explicitly schematic")


def run_case(browser, case: tuple[str, int, int, str, str, str]) -> dict:
    name, width, height, locale, scheme, motion = case
    language = "ru" if locale.startswith("ru") else "en"
    context = browser.new_context(
        viewport={"width": width, "height": height},
        device_scale_factor=1,
        locale=locale,
        color_scheme=scheme,
        reduced_motion=motion,
        accept_downloads=False,
        service_workers="block",
    )
    page = context.new_page()
    js_errors: list[str] = []
    outbound: list[str] = []
    page.on("pageerror", lambda error: js_errors.append(str(error)))
    page.on("request", lambda request: (
        outbound.append(request.url)
        if request.url.startswith(("https://", "http://"))
        and not request.url.startswith(("http://127.0.0.1:5173/", "http://localhost:5173/"))
        else None
    ))

    try:
        response = page.goto(BASE_URL, wait_until="domcontentloaded", timeout=45000)
        ensure(response is not None and response.ok, f"{name}: dev preview unavailable")
        page.locator("#saas-demo-tenant").wait_for(state="visible", timeout=30000)
        ensure(page.locator("html").get_attribute("lang") == language,
               f"{name}: expected {language} language")
        ensure(page.locator("html").get_attribute("data-theme") ==
               ("dark" if scheme == "dark" else "white"),
               f"{name}: theme does not follow system color-scheme")
        ensure(("Синтетические данные" if language == "ru" else "Synthetic data")
               in visible_text(page), f"{name}: missing synthetic-data badge")
        assert_no_document_overflow(page, name + ": initial")
        screenshot(page, name + "-overview.png")

        check_tenants_search_wizard(page, language)
        assert_no_document_overflow(page, name + ": account and network views")
        check_flow(page, language)
        assert_no_document_overflow(page, name + ": request flow")
        screenshot(page, name + "-flow.png")

        if motion == "reduce":
            ensure(page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches"),
                   f"{name}: reduced-motion emulation unavailable")
            duration = page.locator("button[aria-pressed]").first.evaluate(
                "(el) => getComputedStyle(el).transitionDuration")
            ensure(all(float(value.strip().rstrip("s")) == 0 for value in duration.split(",")),
                   f"{name}: flow node transitions not disabled: {duration}")

        ensure(not js_errors, f"{name}: browser JS errors: {js_errors}")
        ensure(not outbound, f"{name}: synthetic preview made external HTTP requests: {outbound}")
        return {"name": name, "status": "passed", "locale": language,
                "theme": scheme, "width": width, "reduced_motion": motion}
    except Exception:
        # Keep evidence even on a failure for fast diagnosis.
        screenshot(page, name + "-failed.png")
        raise
    finally:
        context.close()


def main() -> None:
    results: list[dict] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for case in CASES:
                    print(f"Browser check: {case[0]}", flush=True)
                    results.append(run_case(browser, case))
                    print(f"PASS {case[0]}", flush=True)
            finally:
                browser.close()
    finally:
        (OUTPUT / "results.json").write_text(json.dumps(results, indent=2),
                                             encoding="utf-8")
    print(f"SUCCESS: {len(results)} independent browser configurations", flush=True)


if __name__ == "__main__":
    main()
