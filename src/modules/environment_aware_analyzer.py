"""
Environment-aware vulnerability analyzer for IRIS.

This module provides environment-aware analysis of vulnerability paths
by combining static analysis results with environment metadata.
"""

import json
import os
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
# 추가된 부분 from here
from .environment_knowledge_base import EnvironmentKnowledgeBase
from .dynamic_verification import DynamicVerification
# 추가된 부분 to here


class EnvironmentAwareAnalyzer:
    """Analyzes vulnerabilities with environment context awareness."""
    
    def __init__(self, env_metadata: Dict[str, Any], logger=None):
        self.env_metadata = env_metadata
        self.logger = logger
        # 추가된 부분 from here
        # Initialize environment knowledge base
        self.kb = EnvironmentKnowledgeBase(logger=logger)
        # Initialize dynamic verification
        self.dynamic_verifier = DynamicVerification(env_metadata, logger=logger)
        # 추가된 부분 to here
    
    def analyze_vulnerability_path(self, 
                                 source_location: str,
                                 sink_location: str, 
                                 flow_summary: str,
                                 intermediate_functions: List[str],
                                 sanitizers_applied: List[str],
                                 cwe_id: str) -> Dict[str, Any]:
        """
        Analyze a vulnerability path with environment context.
        
        Args:
            source_location: Location of the source
            sink_location: Location of the sink
            flow_summary: Summary of the data flow
            intermediate_functions: List of intermediate functions
            sanitizers_applied: List of sanitizers applied
            cwe_id: CWE identifier
            
        Returns:
            Analysis result with environment-aware labeling
        """
        # 추가된 부분 from here
        # Prepare environment context for analysis
        env_context = self._prepare_environment_context()
        
        # 추가된 부분 from here
        # Use environment knowledge base for rule-based analysis
        sink_type = self._determine_sink_type(cwe_id, sink_location)
        kb_result = self.kb.evaluate_sink_risk(
            sink_type=sink_type,
            sink_location=sink_location,
            environment_context=env_context,
            sanitizers_applied=sanitizers_applied
        )
        
        # Evaluate sanitizer effectiveness
        sanitizer_effectiveness = {}
        for sanitizer in sanitizers_applied:
            sanitizer_type = self._determine_sanitizer_type(sanitizer)
            effectiveness = self.kb.evaluate_sanitizer_effectiveness(
                sanitizer_type=sanitizer_type,
                environment_context=env_context
            )
            sanitizer_effectiveness[sanitizer] = effectiveness
        
        # Calculate environment-weighted score
        env_score = self.kb.calculate_environment_score(
            sink_type=sink_type,
            environment_context=env_context,
            sanitizers_applied=sanitizers_applied
        )
        
        # Combine KB results with traditional analysis
        analysis_result = self._analyze_by_cwe_type(
            cwe_id, source_location, sink_location, 
            flow_summary, intermediate_functions, 
            sanitizers_applied, env_context
        )
        
        # 추가된 부분 from here
        # Perform dynamic verification if label is "UNCERTAIN_NEEDS_TESTING"
        dynamic_verification = None
        if kb_result["label"] == "UNCERTAIN_NEEDS_TESTING":
            dynamic_verification = self._perform_dynamic_verification(
                cwe_id, sink_location, sanitizers_applied
            )
        
        # Enhance with KB results
        analysis_result.update({
            "kb_risk_score": kb_result["risk_score"],
            "kb_label": kb_result["label"],
            "kb_reasoning": kb_result["reasoning"],
            "kb_rule_ids": kb_result["rule_ids"],
            "environment_score": env_score,
            "sanitizer_effectiveness": sanitizer_effectiveness,
            "environment_factors": kb_result["environment_factors"],
            "dynamic_verification": dynamic_verification
        })
        
        # Update final label based on dynamic verification
        if dynamic_verification and dynamic_verification.get("verified"):
            if dynamic_verification.get("test_result") == "PASS":
                analysis_result["final_label"] = "VULNERABLE_CONFIRMED"
            else:
                analysis_result["final_label"] = "ENVIRONMENT_SAFE"
        else:
            analysis_result["final_label"] = analysis_result.get("label", "UNCERTAIN_NEEDS_TESTING")
        
        return analysis_result
        # 추가된 부분 to here
        # 추가된 부분 to here
        # 추가된 부분 to here
    
    def _prepare_environment_context(self) -> Dict[str, Any]:
        """Prepare environment context for analysis."""
        # 추가된 부분 from here
        return {
            "os": self.env_metadata.get("os", "unknown"),
            "distro": self.env_metadata.get("distro", "unknown"),
            "runtime": self.env_metadata.get("runtime", {}),
            "frameworks": self.env_metadata.get("frameworks", {}),
            "db": self.env_metadata.get("db", {}),
            "policies": self.env_metadata.get("policies", {}),
            "fs": self.env_metadata.get("fs", "unknown"),
            "containerized": self.env_metadata.get("containerized", False),
            "project_specific": self.env_metadata.get("project_specific", {})
        }
        # 추가된 부분 to here
    
    def _analyze_by_cwe_type(self, 
                           cwe_id: str,
                           source_location: str,
                           sink_location: str,
                           flow_summary: str,
                           intermediate_functions: List[str],
                           sanitizers_applied: List[str],
                           env_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability based on CWE type and environment."""
        # 추가된 부분 from here
        if cwe_id == "CWE-078":  # OS Command Injection
            return self._analyze_command_injection(
                source_location, sink_location, flow_summary,
                intermediate_functions, sanitizers_applied, env_context
            )
        elif cwe_id == "CWE-022":  # Path Traversal
            return self._analyze_path_traversal(
                source_location, sink_location, flow_summary,
                intermediate_functions, sanitizers_applied, env_context
            )
        elif cwe_id == "CWE-079":  # Cross-site Scripting
            return self._analyze_xss(
                source_location, sink_location, flow_summary,
                intermediate_functions, sanitizers_applied, env_context
            )
        else:
            # Generic analysis for other CWE types
            return self._analyze_generic(
                source_location, sink_location, flow_summary,
                intermediate_functions, sanitizers_applied, env_context
            )
        # 추가된 부분 to here
    
    def _analyze_command_injection(self, 
                                 source_location: str,
                                 sink_location: str,
                                 flow_summary: str,
                                 intermediate_functions: List[str],
                                 sanitizers_applied: List[str],
                                 env_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze command injection with environment context."""
        # 추가된 부분 from here
        os_type = env_context["os"]
        runtime = env_context["runtime"]
        
        # Check if shell is being used
        shell_used = self._detect_shell_usage(sink_location, intermediate_functions)
        
        # Determine risk level based on environment
        if os_type == "windows":
            if shell_used:
                risk_level = "HIGH"
                label = "VULNERABLE_CONFIRMED"
                reasoning = "Windows shell execution with potential metacharacter injection"
            else:
                risk_level = "MEDIUM"
                label = "UNCERTAIN_NEEDS_TESTING"
                reasoning = "Windows process execution - needs testing for argument injection"
        elif os_type == "linux":
            if shell_used:
                risk_level = "HIGH"
                label = "VULNERABLE_CONFIRMED"
                reasoning = "Linux shell execution with potential metacharacter injection"
            else:
                risk_level = "LOW"
                label = "ENVIRONMENT_SAFE"
                reasoning = "Linux subprocess execution with shell=False is generally safe"
        else:
            risk_level = "MEDIUM"
            label = "UNCERTAIN_NEEDS_TESTING"
            reasoning = "Unknown OS - requires manual verification"
        
        return {
            "label": label,
            "confidence": risk_level,
            "reasoning": reasoning,
            "rule_ids": ["command.exec.shell_usage", f"command.exec.{os_type}"]
        }
        # 추가된 부분 to here
    
    def _analyze_path_traversal(self, 
                              source_location: str,
                              sink_location: str,
                              flow_summary: str,
                              intermediate_functions: List[str],
                              sanitizers_applied: List[str],
                              env_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze path traversal with environment context."""
        # 추가된 부분 from here
        os_type = env_context["os"]
        fs_type = env_context["fs"]
        
        # Check for path normalization
        path_normalized = self._detect_path_normalization(sanitizers_applied, intermediate_functions)
        
        if os_type == "windows":
            if fs_type == "ntfs":
                # Windows NTFS with ADS support
                if path_normalized:
                    risk_level = "MEDIUM"
                    label = "UNCERTAIN_NEEDS_TESTING"
                    reasoning = "Windows NTFS with path normalization - ADS bypass possible"
                else:
                    risk_level = "HIGH"
                    label = "VULNERABLE_CONFIRMED"
                    reasoning = "Windows NTFS without proper path normalization"
            else:
                risk_level = "MEDIUM"
                label = "UNCERTAIN_NEEDS_TESTING"
                reasoning = "Windows with unknown filesystem - requires testing"
        elif os_type == "linux":
            if path_normalized:
                risk_level = "LOW"
                label = "ENVIRONMENT_SAFE"
                reasoning = "Linux with proper path normalization"
            else:
                risk_level = "MEDIUM"
                label = "UNCERTAIN_NEEDS_TESTING"
                reasoning = "Linux without path normalization - symlink traversal possible"
        else:
            risk_level = "MEDIUM"
            label = "UNCERTAIN_NEEDS_TESTING"
            reasoning = "Unknown OS - requires manual verification"
        
        return {
            "label": label,
            "confidence": risk_level,
            "reasoning": reasoning,
            "rule_ids": ["path.traversal.normalization", f"path.traversal.{os_type}"]
        }
        # 추가된 부분 to here
    
    def _analyze_xss(self, 
                    source_location: str,
                    sink_location: str,
                    flow_summary: str,
                    intermediate_functions: List[str],
                    sanitizers_applied: List[str],
                    env_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze XSS with environment context."""
        # 추가된 부분 from here
        frameworks = env_context["frameworks"]
        
        # Check for template engine and version
        template_engine = self._detect_template_engine(frameworks)
        autoescape_enabled = self._detect_autoescape(sanitizers_applied, intermediate_functions)
        
        if template_engine:
            if autoescape_enabled:
                risk_level = "LOW"
                label = "ENVIRONMENT_SAFE"
                reasoning = f"Template engine {template_engine} with autoescape enabled"
            else:
                risk_level = "HIGH"
                label = "VULNERABLE_CONFIRMED"
                reasoning = f"Template engine {template_engine} without autoescape"
        else:
            risk_level = "MEDIUM"
            label = "UNCERTAIN_NEEDS_TESTING"
            reasoning = "No template engine detected - manual verification needed"
        
        return {
            "label": label,
            "confidence": risk_level,
            "reasoning": reasoning,
            "rule_ids": ["xss.template.autoescape", f"xss.template.{template_engine or 'unknown'}"]
        }
        # 추가된 부분 to here
    
    def _analyze_generic(self, 
                        source_location: str,
                        sink_location: str,
                        flow_summary: str,
                        intermediate_functions: List[str],
                        sanitizers_applied: List[str],
                        env_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generic analysis for other CWE types."""
        # 추가된 부분 from here
        return {
            "label": "UNCERTAIN_NEEDS_TESTING",
            "confidence": "MEDIUM",
            "reasoning": "Generic analysis - requires manual verification",
            "rule_ids": ["generic.manual_verification"]
        }
        # 추가된 부분 to here
    
    def _detect_shell_usage(self, sink_location: str, intermediate_functions: List[str]) -> bool:
        """Detect if shell is being used for command execution."""
        # 추가된 부분 from here
        shell_indicators = [
            "shell=True", "Runtime.exec", "ProcessBuilder", "cmd.exe", "/bin/sh", "/bin/bash"
        ]
        
        for indicator in shell_indicators:
            if indicator in sink_location or any(indicator in func for func in intermediate_functions):
                return True
        return False
        # 추가된 부분 to here
    
    def _detect_path_normalization(self, sanitizers_applied: List[str], intermediate_functions: List[str]) -> bool:
        """Detect if path normalization is applied."""
        # 추가된 부분 from here
        normalization_indicators = [
            "normalize", "resolve", "canonical", "realpath", "Path.getCanonicalPath"
        ]
        
        for indicator in normalization_indicators:
            if any(indicator in sanitizer for sanitizer in sanitizers_applied):
                return True
            if any(indicator in func for func in intermediate_functions):
                return True
        return False
        # 추가된 부분 to here
    
    def _detect_template_engine(self, frameworks: Dict[str, Any]) -> Optional[str]:
        """Detect template engine from frameworks."""
        # 추가된 부분 from here
        template_engines = ["jinja2", "django", "freemarker", "thymeleaf", "mustache"]
        
        for engine in template_engines:
            if engine in str(frameworks).lower():
                return engine
        return None
        # 추가된 부분 to here
    
    def _detect_autoescape(self, sanitizers_applied: List[str], intermediate_functions: List[str]) -> bool:
        """Detect if autoescape is enabled."""
        # 추가된 부분 from here
        autoescape_indicators = [
            "autoescape", "escape", "html.escape", "mark_safe", "safe"
        ]
        
        for indicator in autoescape_indicators:
            if any(indicator in sanitizer for sanitizer in sanitizers_applied):
                return True
            if any(indicator in func for func in intermediate_functions):
                return True
        return False
        # 추가된 부분 to here
    
    def _identify_environment_factors(self, 
                                    cwe_id: str,
                                    sink_location: str,
                                    sanitizers_applied: List[str],
                                    env_context: Dict[str, Any]) -> List[str]:
        """Identify specific environment factors that influence the analysis."""
        # 추가된 부분 from here
        factors = []
        
        if cwe_id == "CWE-078":  # Command Injection
            if env_context["os"] == "windows":
                factors.append("Windows command execution behavior")
            elif env_context["os"] == "linux":
                factors.append("Linux shell metacharacter handling")
            
            if self._detect_shell_usage(sink_location, []):
                factors.append("Shell execution detected")
            else:
                factors.append("Process execution without shell")
        
        elif cwe_id == "CWE-022":  # Path Traversal
            if env_context["os"] == "windows" and env_context["fs"] == "ntfs":
                factors.append("Windows NTFS with ADS support")
            elif env_context["os"] == "linux":
                factors.append("Linux symlink handling")
            
            if self._detect_path_normalization(sanitizers_applied, []):
                factors.append("Path normalization applied")
            else:
                factors.append("No path normalization detected")
        
        elif cwe_id == "CWE-079":  # XSS
            template_engine = self._detect_template_engine(env_context["frameworks"])
            if template_engine:
                factors.append(f"Template engine: {template_engine}")
            
            if self._detect_autoescape(sanitizers_applied, []):
                factors.append("Autoescape enabled")
            else:
                factors.append("No autoescape detected")
        
        return factors
        # 추가된 부분 to here
    
    # 추가된 부분 from here
    def _determine_sink_type(self, cwe_id: str, sink_location: str) -> str:
        """Determine sink type based on CWE ID and sink location."""
        if cwe_id == "CWE-078":  # Command Injection
            return "command.exec"
        elif cwe_id == "CWE-022":  # Path Traversal
            return "path.access"
        elif cwe_id == "CWE-079":  # XSS
            return "template.render"
        elif cwe_id == "CWE-094":  # Code Injection
            return "template.render"
        else:
            return "generic"
    
    def _determine_sanitizer_type(self, sanitizer: str) -> str:
        """Determine sanitizer type based on sanitizer name."""
        sanitizer_lower = sanitizer.lower()
        
        if any(keyword in sanitizer_lower for keyword in ["normalize", "resolve", "canonical", "realpath"]):
            return "path.normalize.resolve"
        elif any(keyword in sanitizer_lower for keyword in ["escape", "autoescape"]):
            return "template.autoescape"
        elif any(keyword in sanitizer_lower for keyword in ["escape", "quote"]):
            return "command.escape"
        else:
            return "generic"
    
    # 추가된 부분 from here
    def _perform_dynamic_verification(self, 
                                    cwe_id: str,
                                    sink_location: str,
                                    sanitizers_applied: List[str]) -> Optional[Dict[str, Any]]:
        """Perform dynamic verification for uncertain vulnerabilities."""
        try:
            # Map CWE ID to vulnerability type
            vuln_type_map = {
                "CWE-078": "command_injection",
                "CWE-022": "path_traversal",
                "CWE-079": "template_injection",
                "CWE-094": "template_injection"
            }
            
            vuln_type = vuln_type_map.get(cwe_id, "unknown")
            if vuln_type == "unknown":
                return None
            
            # Generate test payload based on vulnerability type
            test_payload = self._generate_test_payload(vuln_type)
            
            # Perform dynamic verification
            verification_result = self.dynamic_verifier.verify_vulnerability(
                vulnerability_type=vuln_type,
                sink_location=sink_location,
                test_payload=test_payload,
                sanitizers_applied=sanitizers_applied
            )
            
            return verification_result
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Dynamic verification failed: {e}")
            return None
    
    def _generate_test_payload(self, vuln_type: str) -> str:
        """Generate test payload for dynamic verification."""
        payloads = {
            "command_injection": "echo VULNERABLE_TEST",
            "path_traversal": "../../../etc/passwd",
            "template_injection": "{{7*7}}"
        }
        return payloads.get(vuln_type, "test_payload")
    # 추가된 부분 to here
