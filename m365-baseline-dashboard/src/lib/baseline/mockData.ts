import { Findings } from "./types";

export const MOCK_FINDINGS: Findings = {
  organization: {
    tenantId: "898b92b6-2d33-472e-8302-3f82d1c67e91",
    displayName: "Laam Security Demo Tenant",
    verifiedDomains: [
      { name: "laamsecurity.com", isDefault: true, isVerified: true }
    ]
  },
  authorizationPolicy: {
    securityDefaultsEnabled: false,
    allowInvitesFrom: "everyone"
  },
  conditionalAccess: {
    count: 2,
    policies: [
      { displayName: "MFA for Admins", state: "enabled" },
      { displayName: "Block Legacy Auth", state: "enabled" }
    ]
  },
  adminRoles: {
    globalAdmins: 3
  }
};

export const MOCK_FINDINGS_SECURE: Findings = {
  organization: {
    tenantId: "898b92b6-2d33-472e-8302-3f82d1c67e91",
    displayName: "Secure Corp",
    verifiedDomains: [
      { name: "securecorp.com", isDefault: true, isVerified: true }
    ]
  },
  authorizationPolicy: {
    securityDefaultsEnabled: true,
    allowInvitesFrom: "adminsAndGuestInviters"
  },
  conditionalAccess: {
    count: 0,
    policies: []
  },
  adminRoles: {
    globalAdmins: 2
  }
};
