"""
Environment Knowledge Base (E-KB) module for IRIS.

This module provides rule-based environment-specific vulnerability analysis
using the environment knowledge base configuration.
"""

import yaml
import os
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path


class EnvironmentKnowledgeBase:
    """Environment Knowledge Base for rule-based vulnerability analysis."""
    
    def __init__(self, kb_path: str = None, logger=None):
        self.logger = logger
        self.kb_data = self._load_knowledge_base(kb_path)
    
    def _load_knowledge_base(self, kb_path: str = None) -> Dict[str, Any]:
        """Load environment knowledge base from YAML file."""
        # 추가된 부분 from here
        if kb_path is None:
            # Look for KB file in project root
            project_root = Path(__file__).parent.parent.parent
            kb_path = project_root / "environment_knowledge_base.yaml"
        
        try:
            if os.path.exists(kb_path):
                with open(kb_path, 'r', encoding='utf-8') as f:
                    kb_data = yaml.safe_load(f)
                    if self.logger:
                        self.logger.info(f"Loaded environment knowledge base from {kb_path}")
                    return kb_data
            else:
                if self.logger:
                    self.logger.warning(f"Knowledge base file not found: {kb_path}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load knowledge base: {e}")
        
        # Return empty knowledge base if loading fails
        return {
            "sinks": [],
            "sanitizers": [],
            "templates": [],
            "environments": [],
            "scoring": {"base_risk": 5, "environment_weights": {}}
        }
        # 추가된 부분 to here
    
    def evaluate_sink_risk(self, 
                          sink_type: str,
                          sink_location: str,
                          environment_context: Dict[str, Any],
                          sanitizers_applied: List[str] = None) -> Dict[str, Any]:
        """Evaluate sink risk using environment knowledge base."""
        # 추가된 부분 from here
        if sanitizers_applied is None:
            sanitizers_applied = []
        
        # Find applicable sink rules
        applicable_rules = self._find_applicable_sink_rules(sink_type, environment_context)
        
        if not applicable_rules:
            return {
                "risk_score": 0,
                "label": "UNKNOWN",
                "reasoning": "No applicable rules found",
                "rule_ids": [],
                "environment_factors": self._identify_environment_factors(environment_context)
            }
        
        # Evaluate each applicable rule
        risk_scores = []
        rule_reasons = []
        rule_ids = []
        
        for rule in applicable_rules:
            risk_score, reasoning = self._evaluate_sink_rule(rule, sink_location, environment_context, sanitizers_applied)
            risk_scores.append(risk_score)
            rule_reasons.append(reasoning)
            rule_ids.append(rule["id"])
        
        # Calculate final risk score
        final_score = max(risk_scores) if risk_scores else 0
        final_label = self._determine_risk_label(final_score)
        
        return {
            "risk_score": final_score,
            "label": final_label,
            "reasoning": "; ".join(rule_reasons),
            "rule_ids": rule_ids,
            "environment_factors": self._identify_environment_factors(environment_context)
        }
        # 추가된 부분 to here
    
    def evaluate_sanitizer_effectiveness(self, 
                                       sanitizer_type: str,
                                       environment_context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate sanitizer effectiveness using environment knowledge base."""
        # 추가된 부분 from here
        # Find applicable sanitizer rules
        applicable_rules = self._find_applicable_sanitizer_rules(sanitizer_type, environment_context)
        
        if not applicable_rules:
            return {
                "effective": True,
                "confidence": "LOW",
                "reasoning": "No applicable rules found",
                "rule_ids": []
            }
        
        # Evaluate each applicable rule
        effectiveness_scores = []
        rule_reasons = []
        rule_ids = []
        
        for rule in applicable_rules:
            effective, reasoning = self._evaluate_sanitizer_rule(rule, environment_context)
            effectiveness_scores.append(effective)
            rule_reasons.append(reasoning)
            rule_ids.append(rule["id"])
        
        # Determine overall effectiveness
        is_effective = all(effectiveness_scores) if effectiveness_scores else True
        confidence = "HIGH" if len(effectiveness_scores) > 1 else "MEDIUM"
        
        return {
            "effective": is_effective,
            "confidence": confidence,
            "reasoning": "; ".join(rule_reasons),
            "rule_ids": rule_ids
        }
        # 추가된 부분 to here
    
    def calculate_environment_score(self, 
                                  sink_type: str,
                                  environment_context: Dict[str, Any],
                                  sanitizers_applied: List[str] = None) -> int:
        """Calculate environment-weighted risk score."""
        # 추가된 부분 from here
        base_risk = self.kb_data.get("scoring", {}).get("base_risk", 5)
        env_weights = self.kb_data.get("scoring", {}).get("environment_weights", {})
        
        # Get sink-specific weights
        sink_weights = env_weights.get(sink_type, {})
        
        # Calculate environment-specific adjustments
        env_adjustment = 0
        
        # OS-specific adjustments
        os_type = environment_context.get("os", "unknown")
        if f"{sink_type}.{os_type}" in sink_weights:
            env_adjustment += sink_weights[f"{sink_type}.{os_type}"]
        
        # Shell-specific adjustments for command execution
        if sink_type == "command.exec":
            shell_used = self._detect_shell_usage(environment_context)
            if shell_used and "shell_true" in sink_weights:
                env_adjustment += sink_weights["shell_true"]
            elif not shell_used and "shell_false" in sink_weights:
                env_adjustment += sink_weights["shell_false"]
        
        # File system-specific adjustments for path operations
        if sink_type == "path.access":
            fs_type = environment_context.get("fs", "unknown")
            if f"fs_{fs_type}" in sink_weights:
                env_adjustment += sink_weights[f"fs_{fs_type}"]
        
        return max(0, base_risk + env_adjustment)
        # 추가된 부분 to here
    
    def _find_applicable_sink_rules(self, sink_type: str, environment_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find sink rules applicable to the given environment."""
        # 추가된 부분 from here
        applicable_rules = []
        
        for rule in self.kb_data.get("sinks", []):
            if self._rule_applies(rule, environment_context):
                # Check if rule matches sink type
                if (rule["id"] == sink_type or 
                    rule["id"].startswith(f"{sink_type}.") or
                    sink_type in rule["id"]):
                    applicable_rules.append(rule)
        
        return applicable_rules
        # 추가된 부분 to here
    
    def _find_applicable_sanitizer_rules(self, sanitizer_type: str, environment_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find sanitizer rules applicable to the given environment."""
        # 추가된 부분 from here
        applicable_rules = []
        
        for rule in self.kb_data.get("sanitizers", []):
            if self._rule_applies(rule, environment_context):
                # Check if rule matches sanitizer type
                if (rule["id"] == sanitizer_type or 
                    rule["id"].startswith(f"{sanitizer_type}.") or
                    sanitizer_type in rule["id"]):
                    applicable_rules.append(rule)
        
        return applicable_rules
        # 추가된 부분 to here
    
    def _rule_applies(self, rule: Dict[str, Any], environment_context: Dict[str, Any]) -> bool:
        """Check if a rule applies to the given environment context."""
        # 추가된 부분 from here
        applies_if = rule.get("applies_if", {})
        
        for condition_key, condition_values in applies_if.items():
            if condition_key not in environment_context:
                return False
            
            env_value = environment_context[condition_key]
            if isinstance(condition_values, list):
                if env_value not in condition_values:
                    return False
            else:
                if env_value != condition_values:
                    return False
        
        return True
        # 추가된 부분 to here
    
    def _evaluate_sink_rule(self, 
                           rule: Dict[str, Any],
                           sink_location: str,
                           environment_context: Dict[str, Any],
                           sanitizers_applied: List[str]) -> Tuple[int, str]:
        """Evaluate a single sink rule."""
        # 추가된 부분 from here
        risk_score = 0
        reasoning_parts = []
        
        # Check risky conditions
        risky_when = rule.get("risky_when", {})
        for condition, value in risky_when.items():
            if self._condition_met(condition, value, sink_location, environment_context, sanitizers_applied):
                risk_score += 2
                reasoning_parts.append(f"Risky condition met: {condition}")
        
        # Check safe conditions
        safe_when = rule.get("safe_when", {})
        for condition, value in safe_when.items():
            if self._condition_met(condition, value, sink_location, environment_context, sanitizers_applied):
                risk_score -= 1
                reasoning_parts.append(f"Safe condition met: {condition}")
        
        # Add rule-specific notes
        if rule.get("notes"):
            reasoning_parts.append(f"Rule note: {rule['notes']}")
        
        reasoning = "; ".join(reasoning_parts) if reasoning_parts else "No specific conditions met"
        
        return risk_score, reasoning
        # 추가된 부분 to here
    
    def _evaluate_sanitizer_rule(self, 
                                rule: Dict[str, Any],
                                environment_context: Dict[str, Any]) -> Tuple[bool, str]:
        """Evaluate a single sanitizer rule."""
        # 추가된 부분 from here
        # Check invalid conditions
        invalid_when = rule.get("invalid_when", {})
        for condition, value in invalid_when.items():
            if self._condition_met(condition, value, "", environment_context, []):
                return False, f"Invalid condition met: {condition}"
        
        # Check valid conditions
        valid_when = rule.get("valid_when", {})
        if valid_when:
            for condition, value in valid_when.items():
                if self._condition_met(condition, value, "", environment_context, []):
                    return True, f"Valid condition met: {condition}"
        
        # Default to effective if no specific conditions
        return True, "No specific conditions found"
        # 추가된 부분 to here
    
    def _condition_met(self, 
                      condition: str,
                      expected_value: Any,
                      sink_location: str,
                      environment_context: Dict[str, Any],
                      sanitizers_applied: List[str]) -> bool:
        """Check if a condition is met."""
        # 추가된 부분 from here
        if condition == "shell_used":
            return self._detect_shell_usage(environment_context)
        elif condition == "metacharacters_present":
            return self._detect_metacharacters(sink_location)
        elif condition == "args_array_used":
            return self._detect_args_array_usage(sink_location)
        elif condition == "path_normalized":
            return self._detect_path_normalization(sanitizers_applied)
        elif condition == "autoescape_enabled":
            return self._detect_autoescape(sanitizers_applied)
        elif condition == "has_ads":
            return environment_context.get("os") == "windows" and environment_context.get("fs") == "ntfs"
        elif condition == "has_unc":
            return environment_context.get("os") == "windows"
        elif condition == "symlink_follow":
            return environment_context.get("os") in ["linux", "macos"]
        else:
            # Generic condition checking
            return environment_context.get(condition) == expected_value
        # 추가된 부분 to here
    
    def _detect_shell_usage(self, environment_context: Dict[str, Any]) -> bool:
        """Detect if shell is being used."""
        # 추가된 부분 from here
        # This would need to be enhanced based on actual sink analysis
        # For now, return a default value
        return False
        # 추가된 부분 to here
    
    def _detect_metacharacters(self, sink_location: str) -> bool:
        """Detect if metacharacters are present."""
        # 추가된 부분 from here
        metacharacters = ["$", "`", "|", "&", ";", "(", ")", "<", ">", "*", "?", "[", "]", "{", "}"]
        return any(char in sink_location for char in metacharacters)
        # 추가된 부분 to here
    
    def _detect_args_array_usage(self, sink_location: str) -> bool:
        """Detect if args array is used."""
        # 추가된 부분 from here
        args_indicators = ["args", "argv", "subprocess", "ProcessStartInfo"]
        return any(indicator in sink_location.lower() for indicator in args_indicators)
        # 추가된 부분 to here
    
    def _detect_path_normalization(self, sanitizers_applied: List[str]) -> bool:
        """Detect if path normalization is applied."""
        # 추가된 부분 from here
        normalization_indicators = ["normalize", "resolve", "canonical", "realpath"]
        return any(indicator in sanitizer.lower() for sanitizer in sanitizers_applied for indicator in normalization_indicators)
        # 추가된 부분 to here
    
    def _detect_autoescape(self, sanitizers_applied: List[str]) -> bool:
        """Detect if autoescape is enabled."""
        # 추가된 부분 from here
        autoescape_indicators = ["autoescape", "escape", "html.escape"]
        return any(indicator in sanitizer.lower() for sanitizer in sanitizers_applied for indicator in autoescape_indicators)
        # 추가된 부분 to here
    
    def _determine_risk_label(self, risk_score: int) -> str:
        """Determine risk label based on score."""
        # 추가된 부분 from here
        if risk_score >= 3:
            return "VULNERABLE_CONFIRMED"
        elif risk_score >= 1:
            return "UNCERTAIN_NEEDS_TESTING"
        else:
            return "ENVIRONMENT_SAFE"
        # 추가된 부분 to here
    
    def _identify_environment_factors(self, environment_context: Dict[str, Any]) -> List[str]:
        """Identify environment factors that influence the analysis."""
        # 추가된 부분 from here
        factors = []
        
        os_type = environment_context.get("os", "unknown")
        fs_type = environment_context.get("fs", "unknown")
        
        if os_type == "windows":
            factors.append("Windows-specific behavior")
            if fs_type == "ntfs":
                factors.append("NTFS with ADS support")
        elif os_type == "linux":
            factors.append("Linux-specific behavior")
            factors.append("Symlink handling")
        
        return factors
        # 추가된 부분 to here
