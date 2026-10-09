import { getLocale, useT } from "../i18n";
import { setUserLocale } from "../i18n/langSync";

export default function LanguageSwitcher() {
  useT();
  const selected = getLocale() === "en" ? "en" : "ru";
  return (
    <label className="policy-lang-switcher">
      <span>Язык / Language</span>
      <select
        aria-label="Язык / Language"
        value={selected}
        onChange={(event) => setUserLocale(event.target.value as "ru" | "en")}
      >
        <option value="ru">Русский</option>
        <option value="en">English</option>
      </select>
    </label>
  );
}
