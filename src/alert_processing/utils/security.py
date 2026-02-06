"""
Security utilities and validation functions.
"""
import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class SecurityValidator:
    """Security validation utilities for the Alert Processing System."""
    
    def __init__(self):
        self.logger = logger
        
        # Patterns for detecting potentially malicious input
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|\/\*|\*\/)",  # SQL comments
            r"(\bOR\s+1=1\b)",  # Common injection pattern
            r"(\bUNION\s+SELECT\b)",  # Union-based injection
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",  # Event handlers like onclick=
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
        ]
        
        self.command_injection_patterns = [
            r"(\||;|&|\$\(|\`)",  # Command separators and execution
            r"(\.\./){2,}",  # Directory traversal
            r"\b(rm|del|format|shutdown|reboot|kill)\b",  # Dangerous commands
        ]
    
    def validate_alert_data(self, data: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Validate incoming alert data for security issues.
        
        Args:
            data: Alert data to validate
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        try:
            # Check for oversized payloads
            if self._check_size_limits(data, issues):
                return False, issues
            
            # Check for injection patterns in string fields
            self._check_injection_patterns(data, issues)
            
            # Validate specific fields
            self._validate_alert_fields(data, issues)
            
            is_valid = len(issues) == 0
            
            if not is_valid:
                self.logger.warning(f"Security validation failed: {issues}")
            
            return is_valid, issues
            
        except Exception as e:
            self.logger.error(f"Security validation error: {e}")
            return False, [f"Validation error: {str(e)}"]
    
    def _check_size_limits(self, data: Dict[str, Any], issues: List[str]) -> bool:
        """Check for oversized payloads that could indicate DoS attempts."""
        import json
        
        try:
            json_str = json.dumps(data)
            size_mb = len(json_str.encode('utf-8')) / (1024 * 1024)
            
            # Limit alert payload to 10MB
            if size_mb > 10:
                issues.append(f"Alert payload too large: {size_mb:.1f}MB (max 10MB)")
                return True
            
            # Check individual field sizes
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 100000:  # 100KB limit per field
                    issues.append(f"Field '{key}' too large: {len(value)} characters")
                    return True
            
            return False
            
        except Exception as e:
            issues.append(f"Size check error: {str(e)}")
            return True
    
    def _check_injection_patterns(self, data: Dict[str, Any], issues: List[str]):
        """Check for injection attack patterns in string data."""
        
        def check_string_value(value: str, field_path: str):
            if not isinstance(value, str):
                return
            
            # Check for SQL injection patterns
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append(f"Potential SQL injection in field '{field_path}': {pattern}")
            
            # Check for XSS patterns
            for pattern in self.xss_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append(f"Potential XSS in field '{field_path}': {pattern}")
            
            # Check for command injection patterns
            for pattern in self.command_injection_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append(f"Potential command injection in field '{field_path}': {pattern}")
        
        def traverse_data(obj: Any, path: str = ""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    traverse_data(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_path = f"{path}[{i}]"
                    traverse_data(item, new_path)
            elif isinstance(obj, str):
                check_string_value(obj, path)
        
        traverse_data(data)
    
    def _validate_alert_fields(self, data: Dict[str, Any], issues: List[str]):
        """Validate specific alert fields for business logic and security."""
        
        # Validate source field
        source = data.get("source", "")
        if source and not re.match(r'^[a-zA-Z0-9_-]+$', source):
            issues.append("Invalid source format: only alphanumeric, underscore, and hyphen allowed")
        
        # Validate data structure
        alert_data = data.get("data", {})
        if not isinstance(alert_data, dict):
            issues.append("Alert data must be an object")
        
        # Check for required context in action group alerts
        if source == "action_group":
            context = alert_data.get("context", {})
            if not isinstance(context, dict):
                issues.append("Action Group alerts must have context object")
    
    def sanitize_kql_string(self, value: str) -> str:
        """
        Sanitize strings for safe use in KQL queries.
        
        Args:
            value: String value to sanitize
            
        Returns:
            Sanitized string safe for KQL queries
        """
        if not value:
            return ""
        
        # Remove or escape dangerous characters
        sanitized = str(value).replace("'", "''")  # KQL escaping
        sanitized = sanitized.replace('\n', ' ').replace('\r', ' ')
        
        # Remove potential KQL operators and commands
        dangerous_patterns = [
            '|', ';', '--', '/*', '*/', 'drop', 'delete', 'update', 'insert',
            'exec', 'execute', 'sp_', 'xp_', 'union', 'select', 'print'
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(re.escape(pattern), '_', sanitized, flags=re.IGNORECASE)
        
        # Limit length and clean up
        sanitized = sanitized[:100].strip()
        
        return sanitized
    
    def validate_file_upload(self, file_content: bytes, filename: str) -> tuple[bool, List[str]]:
        """Validate uploaded files for security issues."""
        issues = []
        
        try:
            # Check file size (max 50MB)
            if len(file_content) > 50 * 1024 * 1024:
                issues.append("File too large (max 50MB)")
            
            # Check filename for path traversal
            if '../' in filename or '..\\' in filename:
                issues.append("Invalid filename: path traversal detected")
            
            # Check for executable file extensions
            dangerous_extensions = [
                '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.ps1',
                '.sh', '.bash', '.php', '.jsp', '.asp', '.aspx'
            ]
            
            file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
            if f'.{file_ext}' in dangerous_extensions:
                issues.append(f"Dangerous file extension: .{file_ext}")
            
            # Check for malicious file signatures (magic bytes)
            if len(file_content) >= 4:
                # Check for PE executable header
                if file_content[:2] == b'MZ':
                    issues.append("Executable file detected")
                
                # Check for script signatures
                if file_content.startswith(b'#!/'):
                    issues.append("Script file detected")
            
            return len(issues) == 0, issues
            
        except Exception as e:
            return False, [f"File validation error: {str(e)}"]


# Global security validator instance
security_validator = SecurityValidator()