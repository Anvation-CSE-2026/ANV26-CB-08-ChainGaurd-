const POLICIES = Object.freeze({
  strict: {
    id: 'strict',
    label: 'Strict',
    description: 'Acts on suspicious patterns sooner.',
    thresholds: { medium: 20, high: 45, critical: 70 }
  },
  standard: {
    id: 'standard',
    label: 'Standard',
    description: 'Uses the default demonstration response bands.',
    thresholds: { medium: 31, high: 61, critical: 81 }
  },
  baseline: {
    id: 'baseline',
    label: 'Baseline-aware',
    description: 'Leaves more room for known normal high-volume activity.',
    thresholds: { medium: 40, high: 70, critical: 90 }
  }
});

let activePolicyId = 'standard';

function publicPolicy(policy) {
  return { id: policy.id, label: policy.label, description: policy.description, thresholds: { ...policy.thresholds } };
}

function getActivePolicy() {
  return publicPolicy(POLICIES[activePolicyId]);
}

function listPolicies() {
  return Object.values(POLICIES).map(publicPolicy);
}

function setActivePolicy(policyId) {
  if (!Object.hasOwn(POLICIES, policyId)) throw new Error('Choose a valid security policy.');
  activePolicyId = policyId;
  return getActivePolicy();
}

function riskLevelForPolicy(score, policy = getActivePolicy()) {
  if (score < policy.thresholds.medium) return 'low';
  if (score < policy.thresholds.high) return 'medium';
  if (score < policy.thresholds.critical) return 'high';
  return 'critical';
}

module.exports = { getActivePolicy, listPolicies, setActivePolicy, riskLevelForPolicy };
