import {readFileSync} from 'node:fs';
import {describe,expect,test} from 'bun:test';
import YAML from 'yaml';

const path='.github/workflows/custom-management-panel.yml';
const document=YAML.parseDocument(readFileSync(path,'utf8'),{
  uniqueKeys:true,
});
const flow=document.toJS();

describe('Custom Management Center push is verification-only',()=>{
  test('workflow YAML is valid and only expected events can trigger',()=>{
    expect(document.errors).toHaveLength(0);
    expect(Object.keys(flow.on).sort()).toEqual([
      'pull_request','push','workflow_dispatch',
    ]);
    expect(flow.on.push.branches).toEqual(['custom-no-apikey-fun']);
    // PR changes and subsequent changes on custom must both run verification.
    for(const event of ['push','pull_request']){
      expect(flow.on[event].paths).toContain('src/**');
      expect(flow.on[event].paths).toContain('tests/**');
      expect(flow.on[event].paths).toContain('vite.config.ts');
      expect(flow.on[event].paths)
        .toContain('.github/workflows/custom-management-panel.yml');
    }
  });

  test('all events have read-only repository permissions and only verify job',()=>{
    expect(flow.permissions).toEqual({contents:'read'});
    expect(Object.keys(flow.jobs)).toEqual(['verify']);
    const job=flow.jobs.verify;
    expect(job.environment).toBeUndefined();
    expect(job.permissions).toBeUndefined();
    expect(job['timeout-minutes']).toBeLessThanOrEqual(30);
    const uses=job.steps.filter(s=>s.uses).map(s=>s.uses);
    expect(uses).toEqual(['actions/checkout@v4','oven-sh/setup-bun@v2']);
    expect(job.steps.filter(s=>s.run).map(s=>s.run)
      .some(s=>s.includes('bun run verify'))).toBe(true);
  });

  test('neither push nor manual verification can mutate a release',()=>{
    const serialized=JSON.stringify(flow);
    expect(serialized).not.toMatch(
      /GH_TOKEN|gh\s+release|gh\s+api|create.release|upload.release|--clobber|--latest|contents.?write|release\/upload|release\/edit|actions\/upload-artifact|curl\s|wget\s/i,
    );
    const commands=flow.jobs.verify.steps
      .filter(s=>typeof s.run==='string').map(s=>s.run).join('\n');
    expect(commands).toContain('bun install --frozen-lockfile');
    expect(commands).toContain('bun run verify');
    expect(commands).toContain('test -s dist/index.html');
    expect(commands).toContain("grep -q 'saas-demo-tenant'");
    expect(commands).not.toMatch(/(?:^|\n)\s*(?:git\s+push|gh\s+|railway\s+|docker\s+push)/m);
  });
});
