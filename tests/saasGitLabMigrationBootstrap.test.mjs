import {readFileSync} from 'node:fs';
import {describe,expect,test} from 'bun:test';
import YAML from 'yaml';

const src=readFileSync('.gitlab-ci.yml','utf8');
const parsed=YAML.parseDocument(src,{uniqueKeys:true});
const ci=parsed.toJS();
const jobs=['main_verify','release_no_publish',
  'demo_build_default_off','chromium_synthetic','pg16_required_port'];

describe('GitLab.com SaaS bootstrap is read-only and PG16 fail-closed',()=>{
  test('GitLab-native YAML parses and contains expected fixed job topology',()=>{
    expect(parsed.errors).toHaveLength(0);
    expect(ci.stages).toEqual(['verify','browser','database']);
    for(const name of jobs){
      expect(ci[name]).toBeDefined();
      expect(Array.isArray(ci[name].script)).toBe(true);
    }
    expect(ci.default.image).toBe('oven/bun:1.3.14');
    expect(ci.default.before_script).toContain(
      'test "${CI_PROJECT_PATH:-}" = "Bagirov24/Cli-Proxy-API-Management-Center"'
    );
  });

  test('no automatic deploy or release upload on any pipeline job',()=>{
    expect(Object.keys(ci).filter(k=>k.startsWith('deploy'))).toEqual([]);
    expect(ci.stages).not.toContain('deploy');
    const runnable=jobs.filter(n=>n!=='pg16_required_port')
      .map(n=>ci[n].script.join('\n')).join('\n');
    expect(runnable).not.toMatch(
      /(?:railway\s+(?:up|redeploy|delete)|git\s+push|gh\s+release|docker\s+push|kubectl\s+apply)/i
    );
    expect(ci.default.before_script.join('\n')).toContain('RAILWAY_TOKEN');
    expect(ci.default.before_script.join('\n')).toContain('DATABASE_URL');
  });

  test('full PostgreSQL16 remains an explicitly BLOCKING unported requirement',()=>{
    const gate=ci.pg16_required_port;
    expect(gate.stage).toBe('database');
    expect(gate.rules).toHaveLength(2);
    for(const rule of gate.rules){
      expect(rule.when).toBe('manual');
      expect(rule.allow_failure).toBe(false);
    }
    const command=gate.script.join('\n');
    expect(command).toContain('SQL001..026');
    expect(command).toContain('exit 1');
    expect(src).toContain('Do NOT spoof GITHUB_ACTIONS=true');
  });

  test('synthetic demo only in isolated DEV browser and denied in normal bundles',()=>{
    expect(ci.chromium_synthetic.variables.VITE_ENABLE_SAAS_BLUEPRINT_DEMO)
      .toBe('true');
    expect(ci.chromium_synthetic.variables.SAAS_BROWSER_URL)
      .toBe('http://127.0.0.1:5173/#/saas-demo-preview');
    expect(ci.demo_build_default_off.script.join('\n'))
      .toContain('SAAS BLUEPRINT DEMO DENIED');
    expect(ci.release_no_publish.script.join('\n'))
      .toContain('saas-demo-tenant');
  });
});
