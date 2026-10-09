// Strict, reproducible RU/EN overlay for the pinned upstream v0.5.1 source.
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
const root = resolve(process.argv[2] || ".");
function patch(file, source, target, n = 1) {
  const filename = join(root, file);
  const original = readFileSync(filename, "utf8");
  const count = original.split(source).length - 1;
  if (count !== n) throw Error(file + " expected " + n + " substitutions; got " + count + " for " + source.slice(0, 50));
  writeFileSync(filename, original.split(source).join(target));
}
function append(file, extra) {
  const filename = join(root, file);
  writeFileSync(filename, readFileSync(filename, "utf8") + extra);
}
function paths(obj, prefix = "") {
  return Object.entries(obj).flatMap(([k, v]) =>
    v && typeof v === "object" && !Array.isArray(v) ? paths(v, prefix + k + ".") : [prefix + k]);
}
const translations = ["zh-CN", "ru", "en"].map((locale) =>
  JSON.parse(readFileSync(join(root, "web/src/i18n/locales/" + locale + ".json"), "utf8")));
const expected = paths(translations[0]).sort().join("\n");
if (paths(translations[1]).sort().join("\n") !== expected ||
    paths(translations[2]).sort().join("\n") !== expected ||
    /[\u3400-\u9fff]/u.test(JSON.stringify(translations[1]))) {
  throw Error("RU and EN translations must contain every upstream key and no Chinese text in RU");
}
console.log("Verified all " + paths(translations[1]).length + " Russian UI translations.");

patch("web/index.html", '<html lang="zh-CN">', '<html lang="ru">');
patch("web/index.html", "<title>cpa-key-policy 管理面板</title>", "<title>CPA Key Policy — управление ключами</title>");
patch("web/src/i18n/index.ts", 'const FALLBACK: Locale = "zh-CN";', 'const FALLBACK: Locale = "ru";');
patch(
  "web/src/i18n/langSync.ts",
  "// Resolve the locale we should apply, in priority order.",
  [
    '// Explicit user language selection overrides the parent management panel locale.',
    'const USER_LOCALE_KEY = "cpa-key-policy-ui-language";',
    'function readUserLocale(): Locale | null {',
    '  try {',
    '    const value = localStorage.getItem(USER_LOCALE_KEY);',
    '    return value === "ru" || value === "en" ? value : null;',
    '  } catch { return null; }',
    '}',
    'export function setUserLocale(locale: "ru" | "en"): void {',
    '  try { localStorage.setItem(USER_LOCALE_KEY, locale); } catch { /* storage may be unavailable */ }',
    '  document.documentElement.setAttribute("lang", locale);',
    '  setLocale(locale);',
    '}',
    '',
    '// Resolve the locale we should apply, in priority order.'
  ].join("\n")
);
patch(
  "web/src/i18n/langSync.ts",
  "function resolveLocale(): Locale {\n  if (isEmbedded()) {",
  "function resolveLocale(): Locale {\n  const preferred = readUserLocale();\n  if (preferred) return preferred;\n  if (isEmbedded()) {"
);
patch(
  "web/src/i18n/langSync.ts",
  '  return "zh-CN";\n}\n\n// Apply the resolved locale',
  '  return "ru";\n}\n\n// Apply the resolved locale'
);
patch(
  "web/src/i18n/langSync.test.ts",
  '  localStorage.removeItem("cli-proxy-language");',
  '  localStorage.removeItem("cli-proxy-language");\n  localStorage.removeItem("cpa-key-policy-ui-language");',
  2
);
patch(
  "web/src/i18n/langSync.test.ts",
  '    setEmbedded(true, parentHtml);\n    expect(_resolveLocale()).toBe("zh-CN");',
  '    setEmbedded(true, parentHtml);\n    expect(_resolveLocale()).toBe("ru");'
);
patch(
  "web/src/i18n/langSync.test.ts",
  '  it("falls back to zh-CN when nothing is set", () => {\n    setEmbedded(false, document.documentElement);\n    expect(_resolveLocale()).toBe("zh-CN");',
  '  it("falls back to Russian when nothing is set", () => {\n    setEmbedded(false, document.documentElement);\n    expect(_resolveLocale()).toBe("ru");'
);
patch(
  "web/src/i18n/langSync.test.ts",
  '    initLangSync();\n    expect(getLocale()).toBe("zh-CN");',
  '    initLangSync();\n    expect(getLocale()).toBe("ru");'
);
append("web/src/i18n/langSync.test.ts", [
  '',
  'describe("Russian build: user language preference", () => {',
  '  it("prefers English selected by the user over the default Russian document", () => {',
  '    document.documentElement.setAttribute("lang", "ru");',
  '    localStorage.setItem("cpa-key-policy-ui-language", "en");',
  '    expect(_resolveLocale()).toBe("en");',
  '  });',
  '});',
  ''
].join("\n"));
patch(
  "web/src/App.tsx",
  'import { useT } from "./i18n";',
  'import { useT } from "./i18n";\nimport LanguageSwitcher from "./components/LanguageSwitcher";'
);
patch("web/src/App.tsx", '<div className="topnav-actions">', '<div className="topnav-actions">\n          <LanguageSwitcher />');
patch(
  "web/src/pages/Login.tsx",
  'import { useT } from "../i18n";',
  'import { useT } from "../i18n";\nimport LanguageSwitcher from "../components/LanguageSwitcher";'
);
patch("web/src/pages/Login.tsx", '<div className="lp-brand">', '<div className="lp-brand">\n        <LanguageSwitcher />');
writeFileSync(join(root, "web/src/components/LanguageSwitcher.tsx"), readFileSync("/overlay/LanguageSwitcher.tsx", "utf8"));
append("web/src/styles.css", "\n" + readFileSync("/overlay/lang-switcher.css", "utf8") + "\n");
patch("web/src/i18n/locales/ru.json", '"mapping": "Маппинг"', '"mapping": "Маршрутизация"');
patch(
  "internal/plugin/app.go",
  'Description: "Enable or disable this plugin without unloading it."',
  'Description: "Включить или отключить плагин без выгрузки библиотеки."'
);
patch(
  "internal/plugin/app.go",
  'Description: "JSON state file used for key policy changes made through the Management API."',
  'Description: "JSON-файл с клиентскими ключами и правилами. На Railway используйте постоянный том /data."'
);
patch(
  "internal/plugin/app.go",
  'Description: "忽略别名目标的 group，对当前 provider/model 的全部候选凭证执行全局加权轮询。"',
  'Description: "Игнорировать группу учётных записей алиаса и распределять запросы по всем аккаунтам провайдера/модели. Для разделения аккаунтов оставьте отключённым."'
);
patch(
  "internal/plugin/app.go",
  'Description: "Initial downstream key policy list. State file wins after it exists."',
  'Description: "Начальный список клиентских ключей. После создания файла состояния используются данные из него; новые ключи создавайте через интерфейс плагина."'
);
patch(
  "internal/plugin/app.go",
  'Menu: "Key Policy", Description: "Web UI for managing downstream CPA key policies (create keys, pick models)."',
  'Menu: "Политики API-ключей", Description: "Управление клиентскими ключами, моделями и лимитами."'
);
console.log("RU/EN overlay applied without modifying server credentials or plugin state.");
