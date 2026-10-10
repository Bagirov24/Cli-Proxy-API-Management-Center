/** Tiny navigation copy: keep large demo translations out of normal UI bundles. */
const ru = {
  navGroup: 'SaaS · прототип',
  navItem: 'Клиенты и подключения',
  demoBadge: 'Синтетические данные',
};
const en = {
  navGroup: 'SaaS · prototype',
  navItem: 'Clients & connections',
  demoBadge: 'Synthetic data',
};
export function getSaasDemoNavigation(language: string): typeof ru {
  return language.toLowerCase().startsWith('ru') ? ru : en;
}
