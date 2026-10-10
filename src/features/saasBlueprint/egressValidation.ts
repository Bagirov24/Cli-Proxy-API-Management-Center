import type { EgressProfile, ProxyEndpoint } from './domain';

/** This is a STATIC input check, not a substitute for egress firewall / DNS checks. */
export type EndpointProblem =
  | 'hostname-invalid'
  | 'hostname-private-or-reserved'
  | 'port-invalid'
  | 'endpoint-missing'
  | 'endpoint-unexpected'
  | 'connector-id-missing';

const reservedSuffixes = [
  'localhost',
  'local',
  'internal',
  'home',
  'lan',
  'corp',
  'intranet',
  'test',
  'invalid',
  'example',
  'onion',
] as const;

function publicIpv4(hostname: string): boolean | null {
  if (!/^\d+(?:\.\d+){3}$/.test(hostname)) return null;
  // Do not permit octal-looking IPv4 components: parsers can interpret them differently.
  if (hostname.split('.').some((part) => part.length > 1 && part.startsWith('0'))) return false;
  const parts = hostname.split('.').map(Number);
  if (parts.some((part) => !Number.isSafeInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  // Fail closed on private, link-local, CGNAT, benchmark, documentation,
  // multicast and reserved address ranges. This is deliberately conservative.
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 0 || b === 168 || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

/**
 * Reject obvious SSRF destinations and URL credentials at the model boundary.
 * DNS responses MUST also be resolved and enforced at connection time:
 * domains can resolve to internal addresses or change between checks.
 * IPv6 literals are deliberately unsupported until complete validation exists.
 */
export function validateProxyEndpoint(endpoint: ProxyEndpoint): EndpointProblem | null {
  if (!Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) {
    return 'port-invalid';
  }
  const hostname = endpoint.hostname.trim().toLowerCase();
  if (
    hostname.length > 253 ||
    !hostname ||
    hostname !== endpoint.hostname.trim().toLowerCase().replace(/\.$/, '') ||
    /[\/:@\s\\?#\[\]%]/.test(hostname)
  ) {
    return 'hostname-invalid';
  }
  const ipv4 = publicIpv4(hostname);
  if (ipv4 === false) return 'hostname-private-or-reserved';
  if (ipv4 === true) return null;

  const labels = hostname.split('.');
  // Reject single-label hosts, numeric-domain shortcuts and pseudo-TLDs.
  if (
    labels.length < 2 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
    !/[a-z]/.test(labels[labels.length - 1])
  ) {
    return 'hostname-invalid';
  }
  if (reservedSuffixes.includes(labels[labels.length - 1] as (typeof reservedSuffixes)[number])) {
    return 'hostname-private-or-reserved';
  }
  return null;
}

/** No credentials or user-controlled URI strings can be included in a profile. */
export function validateEgressProfileShape(profile: EgressProfile): EndpointProblem | null {
  if (profile.kind === 'direct') {
    return profile.endpoint || profile.connectorId ? 'endpoint-unexpected' : null;
  }
  if (profile.kind === 'vpn-connector') {
    return profile.endpoint
      ? 'endpoint-unexpected'
      : !profile.connectorId || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(profile.connectorId)
        ? 'connector-id-missing'
        : null;
  }
  if (profile.connectorId) return 'endpoint-unexpected';
  if (!profile.endpoint) return 'endpoint-missing';
  return validateProxyEndpoint(profile.endpoint);
}

/** UI-safe summary: credentials are never part of this model. */
export function publicEgressLabel(profile: EgressProfile): string {
  if (profile.kind === 'direct') return 'Direct';
  if (profile.kind === 'vpn-connector') return 'VPN connector';
  if (!profile.endpoint || validateProxyEndpoint(profile.endpoint)) return 'Invalid proxy endpoint';
  return profile.kind.toUpperCase() + ' · ' +
    profile.endpoint.hostname + ':' + String(profile.endpoint.port);
}
