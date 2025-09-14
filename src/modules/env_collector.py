"""
Environment metadata collector for IRIS.

This module collects environment information including OS, runtime versions,
frameworks, and project-specific build configurations.
"""

import os
import json
import platform
import subprocess
import shutil
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class EnvironmentCollector:
    """Collects environment metadata for static analysis and LLM context."""
    
    def __init__(self, project_path: str, logger=None, config_path: str = None):
        self.project_path = project_path
        self.logger = logger
        self.env_data = {}
        self.config = self._load_config(config_path)
    
    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            # Look for config file in project root
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "env_collector_config.yaml"
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    if self.logger:
                        self.logger.info(f"Loaded environment collector config from {config_path}")
                    return config
            else:
                if self.logger:
                    self.logger.warning(f"Config file not found: {config_path}, using defaults")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load config: {e}")
        
        # Return default configuration
        return {
            "enabled": True,
            "collection": {
                "system": {"enabled": True, "collect_distro": True, "collect_container_info": True, "collect_filesystem": True, "collect_shell": True},
                "runtime": {"enabled": True, "collect_python": True, "collect_java": True, "collect_node": True},
                "frameworks": {"enabled": True, "collect_maven": True, "collect_gradle": True, "collect_ant": True},
                "database": {"enabled": True, "detect_drivers": True, "driver_patterns": ["mysql-connector", "postgresql", "h2", "sqlite", "oracle", "mssql"]},
                "security": {"enabled": True, "collect_selinux": True, "collect_apparmor": True, "collect_firewall": True},
                "project": {"enabled": True, "detect_jdk_version": True, "detect_build_tool": True, "extract_dependencies": True}
            },
            "output": {"filename": "env.json", "include_in_results": True, "include_in_prompts": True, "verbose": False},
            "prompt": {"use_env_context": True, "context_format": "detailed"},
            "performance": {"subprocess_timeout": 30, "max_file_size": 1048576, "skip_large_projects": False}
        }
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Collect basic system information."""
        system_info = {
            "os": platform.system().lower(),
            "distro": self._get_distro_info(),
            "containerized": self._is_containerized(),
            "shell": os.environ.get("SHELL", "/bin/bash").split("/")[-1],
            "fs": self._get_filesystem_info()
        }
        return system_info
    
    def collect_runtime_info(self) -> Dict[str, Any]:
        """Collect runtime environment information."""
        runtime_info = {
            "python": self._get_python_version(),
            "java": self._get_java_version(),
            "node": self._get_node_version()
        }
        return runtime_info
    
    def collect_framework_info(self) -> Dict[str, Any]:
        """Collect framework and build tool information."""
        framework_info = {
            "maven": self._get_maven_version(),
            "gradle": self._get_gradle_version(),
            "ant": self._get_ant_version()
        }
        return framework_info
    
    def collect_database_info(self) -> Dict[str, Any]:
        """Collect database driver information."""
        db_info = {
            "driver": self._detect_db_drivers(),
            "version": "unknown"
        }
        return db_info
    
    def collect_security_policies(self) -> Dict[str, Any]:
        """Collect security policy information."""
        policies = {
            "selinux": self._get_selinux_status(),
            "apparmor": self._get_apparmor_status(),
            "firewall": self._get_firewall_status()
        }
        return policies
    
    def collect_project_specific_info(self) -> Dict[str, Any]:
        """Collect project-specific build configuration."""
        project_info = {
            "jdk_version": self._detect_project_jdk(),
            "build_tool": self._detect_build_tool(),
            "build_tool_version": self._detect_build_tool_version(),
            "dependencies": self._extract_dependencies()
        }
        return project_info
    
    def collect_all(self) -> Dict[str, Any]:
        """Collect all environment metadata based on configuration."""
        if not self.config.get("enabled", True):
            if self.logger:
                self.logger.info("Environment collection is disabled in config")
            return {}
        
        self.env_data = {}
        
        # Collect system information if enabled
        if self.config.get("collection", {}).get("system", {}).get("enabled", True):
            self.env_data.update(self.collect_system_info())
        
        # Collect runtime information if enabled
        if self.config.get("collection", {}).get("runtime", {}).get("enabled", True):
            self.env_data["runtime"] = self.collect_runtime_info()
        
        # Collect framework information if enabled
        if self.config.get("collection", {}).get("frameworks", {}).get("enabled", True):
            self.env_data["frameworks"] = self.collect_framework_info()
        
        # Collect database information if enabled
        if self.config.get("collection", {}).get("database", {}).get("enabled", True):
            self.env_data["db"] = self.collect_database_info()
        
        # Collect security policies if enabled
        if self.config.get("collection", {}).get("security", {}).get("enabled", True):
            self.env_data["policies"] = self.collect_security_policies()
        
        # Collect project-specific information if enabled
        if self.config.get("collection", {}).get("project", {}).get("enabled", True):
            self.env_data["project_specific"] = self.collect_project_specific_info()
        
        # Add configuration information
        self.env_data["config"] = self.config
        
        return self.env_data
    
    def save_to_file(self, output_path: str = None) -> None:
        """Save environment metadata to JSON file."""
        if output_path is None:
            # Use configured filename
            filename = self.config.get("output", {}).get("filename", "env.json")
            output_path = os.path.join(self.project_path, filename)
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.env_data, f, indent=2)
        
        if self.logger and self.config.get("output", {}).get("verbose", False):
            self.logger.info(f"Environment metadata saved to {output_path}")
    
    def _get_distro_info(self) -> str:
        """Get Linux distribution information."""
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if line.startswith("ID="):
                            return line.split("=")[1].strip().strip('"')
        except Exception:
            pass
        return platform.system().lower()
    
    def _is_containerized(self) -> bool:
        """Check if running in container."""
        # Check for common container indicators
        container_indicators = [
            "/.dockerenv",
            "/proc/1/cgroup",
            "/run/.containerenv"
        ]
        
        for indicator in container_indicators:
            if os.path.exists(indicator):
                return True
        
        # Check cgroup for container indicators
        try:
            with open("/proc/1/cgroup", "r") as f:
                content = f.read()
                if "docker" in content or "containerd" in content:
                    return True
        except Exception:
            pass
        
        return False
    
    def _get_filesystem_info(self) -> str:
        """Get filesystem type."""
        try:
            result = subprocess.run(["df", "-T", "/"], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    return lines[1].split()[1]
        except Exception:
            pass
        return "unknown"
    
    def _get_python_version(self) -> str:
        """Get Python version."""
        return platform.python_version()
    
    def _get_java_version(self) -> Optional[str]:
        """Get Java version."""
        try:
            result = subprocess.run(["java", "-version"], capture_output=True, text=True)
            if result.returncode == 0:
                version_line = result.stderr.split('\n')[0]
                # Extract version number from "openjdk version "1.8.0_xxx""
                if "version" in version_line:
                    version = version_line.split("version")[1].strip().strip('"')
                    return version.split()[0]
        except Exception:
            pass
        return None
    
    def _get_node_version(self) -> Optional[str]:
        """Get Node.js version."""
        try:
            result = subprocess.run(["node", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().lstrip('v')
        except Exception:
            pass
        return None
    
    def _get_maven_version(self) -> Optional[str]:
        """Get Maven version."""
        try:
            result = subprocess.run(["mvn", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                if "Apache Maven" in version_line:
                    return version_line.split("Apache Maven")[1].strip().split()[0]
        except Exception:
            pass
        return None
    
    def _get_gradle_version(self) -> Optional[str]:
        """Get Gradle version."""
        try:
            result = subprocess.run(["gradle", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "Gradle" in line and "version" in line:
                        return line.split()[-1]
        except Exception:
            pass
        return None
    
    def _get_ant_version(self) -> Optional[str]:
        """Get Apache Ant version."""
        try:
            result = subprocess.run(["ant", "-version"], capture_output=True, text=True)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                if "Apache Ant" in version_line:
                    return version_line.split("Apache Ant")[1].strip().split()[0]
        except Exception:
            pass
        return None
    
    def _detect_db_drivers(self) -> str:
        """Detect database drivers in project."""
        if not self.config.get("collection", {}).get("database", {}).get("detect_drivers", True):
            return "none"
        
        db_drivers = []
        
        # Get driver patterns from config
        driver_patterns = self.config.get("collection", {}).get("database", {}).get("driver_patterns", [
            "mysql-connector", "postgresql", "h2", "sqlite", "oracle", "mssql"
        ])
        
        max_file_size = self.config.get("performance", {}).get("max_file_size", 1048576)
        
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith(('.jar', '.pom', '.xml', '.gradle')):
                    file_path = os.path.join(root, file)
                    try:
                        # Check file size before reading
                        if os.path.getsize(file_path) > max_file_size:
                            continue
                            
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()
                            for pattern in driver_patterns:
                                if pattern in content:
                                    db_drivers.append(pattern)
                    except Exception:
                        pass
        
        return ", ".join(set(db_drivers)) if db_drivers else "none"
    
    def _get_selinux_status(self) -> str:
        """Get SELinux status."""
        try:
            result = subprocess.run(["getenforce"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().lower()
        except Exception:
            pass
        return "disabled"
    
    def _get_apparmor_status(self) -> str:
        """Get AppArmor status."""
        try:
            result = subprocess.run(["aa-status"], capture_output=True, text=True)
            if result.returncode == 0:
                return "enabled"
        except Exception:
            pass
        return "disabled"
    
    def _get_firewall_status(self) -> str:
        """Get firewall status."""
        try:
            # Check for ufw
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if result.returncode == 0:
                if "active" in result.stdout.lower():
                    return "ufw_active"
        except Exception:
            pass
        
        try:
            # Check for iptables
            result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return "iptables_active"
        except Exception:
            pass
        
        return "unknown"
    
    def _detect_project_jdk(self) -> Optional[str]:
        """Detect JDK version used by project."""
        # Check for JAVA_HOME or java version in build files
        java_home = os.environ.get("JAVA_HOME", "")
        if java_home and "java" in java_home.lower():
            if "1.8" in java_home or "8" in java_home:
                return "8"
            elif "11" in java_home:
                return "11"
            elif "17" in java_home:
                return "17"
        
        # Check build files for Java version
        for build_file in ["pom.xml", "build.gradle", "build.gradle.kts"]:
            build_path = os.path.join(self.project_path, build_file)
            if os.path.exists(build_path):
                try:
                    with open(build_path, 'r') as f:
                        content = f.read()
                        if "java.version" in content or "sourceCompatibility" in content:
                            # Extract version from build file
                            import re
                            version_match = re.search(r'java\.version["\']?\s*[=:]\s*["\']?(\d+)', content)
                            if version_match:
                                return version_match.group(1)
                except Exception:
                    pass
        
        return None
    
    def _detect_build_tool(self) -> str:
        """Detect primary build tool used by project."""
        if os.path.exists(os.path.join(self.project_path, "pom.xml")):
            return "maven"
        elif os.path.exists(os.path.join(self.project_path, "build.gradle")) or \
             os.path.exists(os.path.join(self.project_path, "build.gradle.kts")):
            return "gradle"
        elif os.path.exists(os.path.join(self.project_path, "build.xml")):
            return "ant"
        else:
            return "unknown"
    
    def _detect_build_tool_version(self) -> Optional[str]:
        """Detect version of build tool used."""
        build_tool = self._detect_build_tool()
        
        if build_tool == "maven":
            return self._get_maven_version()
        elif build_tool == "gradle":
            return self._get_gradle_version()
        elif build_tool == "ant":
            return self._get_ant_version()
        
        return None
    
    def _extract_dependencies(self) -> Dict[str, Any]:
        """Extract project dependencies."""
        dependencies = {
            "maven_deps": [],
            "gradle_deps": [],
            "jar_files": []
        }
        
        # Extract Maven dependencies
        pom_path = os.path.join(self.project_path, "pom.xml")
        if os.path.exists(pom_path):
            dependencies["maven_deps"] = self._parse_maven_dependencies(pom_path)
        
        # Extract Gradle dependencies
        gradle_path = os.path.join(self.project_path, "build.gradle")
        if os.path.exists(gradle_path):
            dependencies["gradle_deps"] = self._parse_gradle_dependencies(gradle_path)
        
        # Find JAR files
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith('.jar'):
                    dependencies["jar_files"].append(os.path.join(root, file))
        
        return dependencies
    
    def _parse_maven_dependencies(self, pom_path: str) -> list:
        """Parse Maven dependencies from pom.xml."""
        deps = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(pom_path)
            root = tree.getroot()
            
            # Handle namespace
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            for dependency in root.findall('.//maven:dependency', ns):
                group_id = dependency.find('maven:groupId', ns)
                artifact_id = dependency.find('maven:artifactId', ns)
                version = dependency.find('maven:version', ns)
                
                if group_id is not None and artifact_id is not None:
                    dep_info = {
                        "group": group_id.text,
                        "artifact": artifact_id.text,
                        "version": version.text if version is not None else "unknown"
                    }
                    deps.append(dep_info)
        except Exception:
            pass
        
        return deps
    
    def _parse_gradle_dependencies(self, gradle_path: str) -> list:
        """Parse Gradle dependencies from build.gradle."""
        deps = []
        try:
            with open(gradle_path, 'r') as f:
                content = f.read()
                import re
                
                # Simple regex to find dependencies
                dep_pattern = r"implementation\s+['\"]([^'\"]+)['\"]"
                matches = re.findall(dep_pattern, content)
                
                for match in matches:
                    if ':' in match:
                        parts = match.split(':')
                        if len(parts) >= 2:
                            dep_info = {
                                "group": parts[0],
                                "artifact": parts[1],
                                "version": parts[2] if len(parts) > 2 else "unknown"
                            }
                            deps.append(dep_info)
        except Exception:
            pass
        
        return deps
