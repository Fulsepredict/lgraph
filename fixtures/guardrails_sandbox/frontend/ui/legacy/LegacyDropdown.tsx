// Исключённая папка legacy: здесь <select> НЕ должен вызывать срабатывание GR-UI-SELECT
export function LegacyDropdown() {
  return <select><option>Old</option></select>;
}
