#!/usr/bin/env python3
"""
Trigger reanalysis script for IRIS environment-aware analysis.

This script detects environment changes and triggers reanalysis
when necessary.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any
import hashlib
import yaml


class ReanalysisTrigger:
    """Triggers reanalysis based on environment changes."""
    
    def __init__(self, project_root: str = None):
        self.project_root = project_root or os.getcwd()
        self.iris_root = Path(self.project_root) / "iris"
        self.data_dir = self.iris_root / "data"
        self.projects_dir = self.data_dir / "project-sources"
        
        # Files that trigger reanalysis
        self.trigger_files = [
            "environment.yml",
            "pom.xml", 
            "build.gradle",
            "Dockerfile",
            "environment_knowledge_base.yaml",
            "env_collector_config.yaml"
        ]
    
    def detect_changes(self, changed_files: List[str]) -> Dict[str, Any]:
        """Detect what type of changes occurred."""
        # 추가된 부분 from here
        changes = {
            "environment_deps": False,
            "build_config": False,
            "knowledge_base": False,
            "collector_config": False,
            "docker_config": False,
            "affected_projects": []
        }
        
        for file_path in changed_files:
            file_name = os.path.basename(file_path)
            
            if file_name in ["environment.yml", "requirements.txt", "package.json"]:
                changes["environment_deps"] = True
                changes["affected_projects"] = self._find_affected_projects("all")
            
            elif file_name in ["pom.xml", "build.gradle", "build.xml"]:
                changes["build_config"] = True
                changes["affected_projects"] = self._find_affected_projects("java")
            
            elif file_name == "environment_knowledge_base.yaml":
                changes["knowledge_base"] = True
                changes["affected_projects"] = self._find_affected_projects("all")
            
            elif file_name == "env_collector_config.yaml":
                changes["collector_config"] = True
                changes["affected_projects"] = self._find_affected_projects("all")
            
            elif file_name == "Dockerfile":
                changes["docker_config"] = True
                changes["affected_projects"] = self._find_affected_projects("all")
        
        return changes
        # 추가된 부분 to here
    
    def _find_affected_projects(self, project_type: str) -> List[str]:
        """Find projects affected by the changes."""
        # 추가된 부분 from here
        affected_projects = []
        
        if not self.projects_dir.exists():
            return affected_projects
        
        for project_dir in self.projects_dir.iterdir():
            if project_dir.is_dir():
                # Check if project has env.json (indicating it was analyzed)
                env_json_path = project_dir / "env.json"
                if env_json_path.exists():
                    affected_projects.append(project_dir.name)
        
        return affected_projects
        # 추가된 부분 to here
    
    def trigger_reanalysis(self, 
                          reason: str,
                          project: str = None,
                          changed_files: List[str] = None) -> bool:
        """Trigger reanalysis for affected projects."""
        # 추가된 부분 from here
        print(f"Triggering reanalysis: {reason}")
        
        if changed_files:
            changes = self.detect_changes(changed_files)
            affected_projects = changes["affected_projects"]
        else:
            affected_projects = self._find_affected_projects("all")
        
        if project:
            affected_projects = [project]
        
        if not affected_projects:
            print("No projects found for reanalysis")
            return True
        
        success_count = 0
        total_count = len(affected_projects)
        
        for project_name in affected_projects:
            print(f"Reanalyzing project: {project_name}")
            
            try:
                # Run IRIS analysis for the project
                result = self._run_iris_analysis(project_name, reason)
                if result:
                    success_count += 1
                    print(f"✓ Successfully reanalyzed {project_name}")
                else:
                    print(f"✗ Failed to reanalyze {project_name}")
            
            except Exception as e:
                print(f"✗ Error reanalyzing {project_name}: {e}")
        
        print(f"Reanalysis completed: {success_count}/{total_count} projects successful")
        return success_count == total_count
        # 추가된 부분 to here
    
    def _run_iris_analysis(self, project_name: str, reason: str) -> bool:
        """Run IRIS analysis for a specific project."""
        # 추가된 부분 from here
        try:
            # Change to iris directory
            os.chdir(self.iris_root)
            
            # Determine CWE queries to run based on project
            cwe_queries = self._get_cwe_queries_for_project(project_name)
            
            for cwe_query in cwe_queries:
                cmd = [
                    "python", "src/iris.py",
                    "--query", cwe_query,
                    "--run-id", f"reanalysis_{reason}",
                    project_name
                ]
                
                print(f"Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode != 0:
                    print(f"Analysis failed for {cwe_query}: {result.stderr}")
                    return False
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"Analysis timed out for {project_name}")
            return False
        except Exception as e:
            print(f"Error running analysis for {project_name}: {e}")
            return False
        # 추가된 부분 to here
    
    def _get_cwe_queries_for_project(self, project_name: str) -> List[str]:
        """Get CWE queries to run for a specific project."""
        # 추가된 부분 from here
        # Default CWE queries - can be customized per project
        default_queries = [
            "cwe-022wLLM",  # Path Traversal
            "cwe-078wLLM",  # Command Injection
            "cwe-079wLLM",  # XSS
            "cwe-094wLLM"   # Code Injection
        ]
        
        # Check if project has specific CWE configuration
        project_config_path = self.projects_dir / project_name / "cwe_config.json"
        if project_config_path.exists():
            try:
                with open(project_config_path, 'r') as f:
                    config = json.load(f)
                    return config.get("cwe_queries", default_queries)
            except Exception:
                pass
        
        return default_queries
        # 추가된 부분 to here
    
    def validate_environment(self) -> bool:
        """Validate that the environment is ready for reanalysis."""
        # 추가된 부분 from here
        print("Validating environment...")
        
        # Check if iris directory exists
        if not self.iris_root.exists():
            print(f"✗ IRIS directory not found: {self.iris_root}")
            return False
        
        # Check if required files exist
        required_files = [
            "src/iris.py",
            "environment_knowledge_base.yaml",
            "env_collector_config.yaml"
        ]
        
        for file_path in required_files:
            full_path = self.iris_root / file_path
            if not full_path.exists():
                print(f"✗ Required file not found: {file_path}")
                return False
        
        # Check if data directory exists
        if not self.data_dir.exists():
            print(f"✗ Data directory not found: {self.data_dir}")
            return False
        
        print("✓ Environment validation passed")
        return True
        # 추가된 부분 to here
    
    def generate_reanalysis_report(self, 
                                 affected_projects: List[str],
                                 reason: str) -> Dict[str, Any]:
        """Generate a reanalysis report."""
        # 추가된 부분 from here
        report = {
            "timestamp": self._get_timestamp(),
            "reason": reason,
            "affected_projects": affected_projects,
            "total_projects": len(affected_projects),
            "environment_changes": self._get_environment_changes(),
            "reanalysis_status": "completed"
        }
        
        # Save report
        report_path = self.iris_root / "reanalysis_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
        # 추가된 부분 to here
    
    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        # 추가된 부분 from here
        from datetime import datetime
        return datetime.now().isoformat()
        # 추가된 부분 to here
    
    def _get_environment_changes(self) -> Dict[str, Any]:
        """Get summary of environment changes."""
        # 추가된 부분 from here
        changes = {
            "files_modified": [],
            "dependencies_updated": False,
            "config_updated": False
        }
        
        # This would be populated based on actual change detection
        # For now, return empty structure
        return changes
        # 추가된 부분 to here


def main():
    """Main function."""
    # 추가된 부분 from here
    parser = argparse.ArgumentParser(description="Trigger IRIS reanalysis")
    parser.add_argument("--reason", required=True, help="Reason for reanalysis")
    parser.add_argument("--project", help="Specific project to reanalyze")
    parser.add_argument("--changed-files", help="Comma-separated list of changed files")
    parser.add_argument("--validate-only", action="store_true", help="Only validate environment")
    
    args = parser.parse_args()
    
    # Initialize trigger
    trigger = ReanalysisTrigger()
    
    # Validate environment
    if not trigger.validate_environment():
        sys.exit(1)
    
    if args.validate_only:
        print("Environment validation completed successfully")
        sys.exit(0)
    
    # Parse changed files
    changed_files = []
    if args.changed_files:
        changed_files = [f.strip() for f in args.changed_files.split(",")]
    
    # Trigger reanalysis
    success = trigger.trigger_reanalysis(
        reason=args.reason,
        project=args.project,
        changed_files=changed_files
    )
    
    if success:
        print("Reanalysis completed successfully")
        sys.exit(0)
    else:
        print("Reanalysis completed with errors")
        sys.exit(1)
    # 추가된 부분 to here


if __name__ == "__main__":
    main()
