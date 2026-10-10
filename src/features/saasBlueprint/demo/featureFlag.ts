/** Explicit opt-in, default OFF in normal build and GitHub release. */
export const SAAS_BLUEPRINT_DEMO_ENABLED =
  import.meta.env.VITE_ENABLE_SAAS_BLUEPRINT_DEMO === 'true';
