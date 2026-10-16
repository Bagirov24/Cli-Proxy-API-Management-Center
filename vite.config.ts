import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';
import path from 'path';
import { execSync } from 'child_process';
import fs from 'fs';

// Get version from environment, git tag, or package.json
function getVersion(): string {
  // 1. Environment variable (set by GitHub Actions)
  if (process.env.VERSION) {
    return process.env.VERSION;
  }

  // 2. Try git tag
  try {
    const gitTag = execSync('git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo ""', { encoding: 'utf8' }).trim();
    if (gitTag) {
      return gitTag;
    }
  } catch {
    // Git not available or no tags
  }

  // 3. Fall back to package.json version
  try {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'package.json'), 'utf8'));
    if (pkg.version && pkg.version !== '0.0.0') {
      return pkg.version;
    }
  } catch {
    // package.json not readable
  }

  return 'dev';
}

// https://vitejs.dev/config/
// The build flag alone must NEVER turn an ordinary/release bundle into a
// synthetic SaaS UI. A preview is allowed only for local DEV or an explicitly
// isolated pull-request CI job that never deploys an artifact.
const saasDemoRequested = process.env.VITE_ENABLE_SAAS_BLUEPRINT_DEMO === 'true';

export default defineConfig(({ command, mode }) => {
  const localDevPreview = command === 'serve' && mode === 'development';
  const isolatedPullRequestPreview =
    command === 'build' &&
    process.env.GITHUB_ACTIONS === 'true' &&
    process.env.GITHUB_EVENT_NAME === 'pull_request' &&
    process.env.SAAS_BLUEPRINT_SYNTHETIC_CI_BUILD === 'true';

  if (saasDemoRequested && !localDevPreview && !isolatedPullRequestPreview) {
    throw new Error(
      'SAAS BLUEPRINT DEMO DENIED: opt-in is allowed only in local DEV ' +
      'or an explicitly isolated synthetic pull-request CI build; ' +
      'never in an ordinary production/release bundle.'
    );
  }

  const saasDemoEnabled =
    saasDemoRequested && (localDevPreview || isolatedPullRequestPreview);

  return {
  plugins: [
    react(),
    viteSingleFile({
      removeViteModuleLoader: true
    })
  ],
  define: {
    __APP_VERSION__: JSON.stringify(getVersion()),
    __SAAS_BLUEPRINT_DEMO_ENABLED__: JSON.stringify(saasDemoEnabled)
  },
  resolve: {
    alias: {
      // The production bundle resolves this import to a zero-cost stub.
      // Vite singlefile would otherwise inline lazy demo code, even when route is hidden.
      '@/features/saasBlueprint/demo/SaasDemoRoute': path.resolve(
        __dirname,
        saasDemoEnabled
          ? './src/features/saasBlueprint/demo/SaasDemoRoute.tsx'
          : './src/features/saasBlueprint/demo/SaasDemoRouteDisabled.tsx'
      ),
      '@': path.resolve(__dirname, './src')
    }
  },
  css: {
    modules: {
      localsConvention: 'camelCase',
      generateScopedName: '[name]__[local]___[hash:base64:5]'
    },
    preprocessorOptions: {
      scss: {
        additionalData: `@use "@/styles/variables.scss" as *;`
      }
    }
  },
  build: {
    target: 'es2020',
    outDir: 'dist',
    assetsInlineLimit: 100000000,
    chunkSizeWarningLimit: 100000000,
    cssCodeSplit: false,
    rolldownOptions: {
      output: {
        codeSplitting: false
      }
    }
  }
  };
});
