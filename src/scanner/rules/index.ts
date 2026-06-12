// Rules index — exports all detection rules as a registry
import { DetectionRule } from '../../types';
import { codeExecutionRule } from './code-execution';
import { dataExfiltrationRule } from './data-exfiltration';
import { authBypassRule } from './auth-bypass';
import { injectionRule } from './injection';
import { configPoisoningRule } from './config-poisoning';
import { behaviorAnomalyRule } from './behavior-anomaly';
import { dependencyChainRule } from './dependency-chain';
import { permissionEscalationRule } from './permission-escalation';

/** All detection rules in the order they should be executed */
export const allRules: DetectionRule[] = [
  codeExecutionRule,
  dataExfiltrationRule,
  authBypassRule,
  injectionRule,
  configPoisoningRule,
  behaviorAnomalyRule,
  dependencyChainRule,
  permissionEscalationRule,
];

/** Get a rule by its ID */
export function getRuleById(id: string): DetectionRule | undefined {
  return allRules.find(r => r.id === id);
}

/** Get all rule IDs */
export function getAllRuleIds(): string[] {
  return allRules.map(r => r.id);
}

/** Get rules by category */
export function getRulesByCategory(category: string): DetectionRule[] {
  return allRules.filter(r => r.category === category);
}
