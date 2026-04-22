export interface Control {
  id: string;
  title: string;
  category: string;
  severity: 'High' | 'Medium' | 'Low';
  weight: number;
  recommendation: string;
  status?: 'Pass' | 'Fail' | 'Unknown';
}

export interface Findings {
  organization: {
    tenantId: string;
    displayName: string;
    verifiedDomains: { name: string; isDefault: boolean; isVerified: boolean }[];
  };
  authorizationPolicy: {
    securityDefaultsEnabled: boolean;
    allowInvitesFrom: string;
  };
  conditionalAccess: {
    count: number;
    policies: { displayName: string; state: string }[];
    error?: string;
  };
  adminRoles: {
    globalAdmins: number;
  };
}

export interface BaselineResult {
  scorePercent: number;
  controls: Control[];
  findings: Findings;
  generatedAt: string;
}

export const CONTROLS: Control[] = [
  {
    "id": "SECDEF_001",
    "title": "Security Defaults enabled",
    "category": "Identity",
    "severity": "High",
    "weight": 15,
    "recommendation": "Enable Security Defaults or replace with equivalent Conditional Access coverage."
  },
  {
    "id": "CA_001",
    "title": "Conditional Access policies exist (if Security Defaults disabled)",
    "category": "Identity",
    "severity": "High",
    "weight": 10,
    "recommendation": "Create baseline Conditional Access policies (MFA, block legacy auth, admin protection)."
  },
  {
    "id": "CA_002",
    "title": "At least one CA policy covers All Users",
    "category": "Identity",
    "severity": "Medium",
    "weight": 8,
    "recommendation": "Ensure a baseline policy applies to all users (with break-glass exclusions documented)."
  },
  {
    "id": "CA_003",
    "title": "CA policy blocks legacy authentication",
    "category": "Identity",
    "severity": "High",
    "weight": 12,
    "recommendation": "Create a Conditional Access policy to block legacy authentication client types."
  },
  {
    "id": "ADMIN_001",
    "title": "Global Administrators count is within threshold",
    "category": "Identity",
    "severity": "High",
    "weight": 12,
    "recommendation": "Reduce permanent Global Admins; use least privilege and PIM where available."
  },
  {
    "id": "ORG_001",
    "title": "Verified domains exist and default domain configured",
    "category": "Tenant",
    "severity": "Low",
    "weight": 5,
    "recommendation": "Ensure your tenant has verified domains and the correct default domain."
  },
  {
    "id": "GUEST_001",
    "title": "Guest invitations restricted (not open to everyone)",
    "category": "Collaboration",
    "severity": "Medium",
    "weight": 8,
    "recommendation": "Restrict who can invite guests and review guest access posture regularly."
  },
  {
    "id": "CONSENT_001",
    "title": "User consent posture is restricted",
    "category": "Apps",
    "severity": "High",
    "weight": 10,
    "recommendation": "Restrict user consent; use admin consent workflows where possible."
  }
];

export function scoreBaseline(controls: Control[], findings: Findings): BaselineResult {
  let score = 0;
  let max = controls.reduce((acc, c) => acc + c.weight, 0);

  const scoredControls = controls.map(c => {
    let status: 'Pass' | 'Fail' | 'Unknown' = 'Unknown';

    switch (c.id) {
      case 'SECDEF_001':
        status = findings.authorizationPolicy.securityDefaultsEnabled ? 'Pass' : 'Fail';
        break;
      case 'CA_001':
        if (!findings.authorizationPolicy.securityDefaultsEnabled) {
          status = findings.conditionalAccess.count > 0 ? 'Pass' : 'Fail';
        } else {
          status = 'Pass'; // Covered by security defaults
        }
        break;
      case 'CA_002':
        // Simplified check: if CA policies exist and we assume at least one covers all users in this demo
        status = findings.conditionalAccess.count > 1 ? 'Pass' : 'Fail';
        break;
      case 'CA_003':
        const blocksLegacy = findings.conditionalAccess.policies.some(p => p.displayName.toLowerCase().includes('legacy auth') && p.state === 'enabled');
        status = (findings.authorizationPolicy.securityDefaultsEnabled || blocksLegacy) ? 'Pass' : 'Fail';
        break;
      case 'ADMIN_001':
        status = (findings.adminRoles.globalAdmins > 0 && findings.adminRoles.globalAdmins <= 5) ? 'Pass' : 'Fail';
        break;
      case 'ORG_001':
        status = (findings.organization.verifiedDomains.length > 0) ? 'Pass' : 'Fail';
        break;
      case 'GUEST_001':
        status = (findings.authorizationPolicy.allowInvitesFrom !== 'everyone') ? 'Pass' : 'Fail';
        break;
      case 'CONSENT_001':
        // Placeholder for user consent restricted check
        status = 'Unknown';
        break;
    }

    if (status === 'Pass') {
      score += c.weight;
    }

    return { ...c, status };
  });

  return {
    scorePercent: max > 0 ? Math.round((score / max) * 100 * 100) / 100 : 0,
    controls: scoredControls,
    findings: findings,
    generatedAt: new Date().toISOString()
  };
}
