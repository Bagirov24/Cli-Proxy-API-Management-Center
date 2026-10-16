import { lazy, Suspense } from 'react';
import { SaasDemoErrorBoundary } from './SaasDemoErrorBoundary';

const SaasBlueprintDemoPage = lazy(() =>
  import('./SaasBlueprintDemoPage').then((module) => ({
    default: module.SaasBlueprintDemoPage,
  }))
);

/**
 * Shared entry for optional authenticated Management Center tab and local-only
 * unauthenticated design review. Contains exclusively synthetic fixture data.
 */
export function SaasDemoRoute() {
  return (
    <SaasDemoErrorBoundary>
      <Suspense fallback={<p role="status">Loading SaaS demo / Загрузка макета SaaS...</p>}>
        <SaasBlueprintDemoPage />
      </Suspense>
    </SaasDemoErrorBoundary>
  );
}
