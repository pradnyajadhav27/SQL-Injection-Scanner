"""
SQL Injection Detection Module
Educational and Authorized Testing Only
Detects SQL injection vulnerabilities with false positive identification
"""

import re
from typing import Dict, List, Tuple

class SQLInjectionDetector:
    """
    Detects SQL injection vulnerabilities by analyzing HTTP responses
    Includes false positive detection for non-database endpoints
    """
    
    def __init__(self):
        # SQL error patterns for database detection
        self.sql_error_patterns = [
            # MySQL errors
            r"mysql_fetch_array\(\)",
            r"mysql_fetch_assoc\(\)",
            r"mysql_num_rows\(\)",
            r"mysql_error\(\)",
            r"Warning: mysql_",
            r"MySQL syntax error",
            r"SQLSTATE\[",
            r"SQL syntax.*MySQL",
            r"mysqli_query\(\)",
            r"mysqli_fetch_",
            
            # PostgreSQL errors
            r"pg_query\(\)",
            r"pg_fetch_array\(\)",
            r"PostgreSQL query failed",
            r"ERROR: syntax error at or near",
            r"invalid input syntax for",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            
            # SQL Server errors
            r"Microsoft OLE DB Provider",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
            r"mssql_query\(\)",
            r"sqlsrv_query\(\)",
            
            # Oracle errors
            r"ORA-\d{5}",
            r"Oracle error",
            r"OCIExecute\(\)",
            r"ORA-",
            
            # SQLite errors
            r"SQLite\.JDBCDriver",
            r"SQLiteException",
            r"SQLITE_ERROR",
            r"sqlite_query\(\)",
            
            # General SQL errors
            r"SQL syntax.*near",
            r"syntax error",
            r"unexpected end of SQL command",
            r"quoted string not properly terminated",
            r"unterminated string",
            r"SQL command not properly ended",
            
            # Database function indicators
            r"SELECT.*FROM",
            r"INSERT.*INTO",
            r"UPDATE.*SET",
            r"DELETE.*FROM",
            r"DROP TABLE",
            r"CREATE TABLE",
        ]
        
        # Non-database response patterns (for false positive detection)
        self.non_database_patterns = [
            # JSON/API responses
            r'"args":',
            r'"url":',
            r'"headers":',
            r'"origin":',
            r'"form":',
            r'"files":',
            r'"json":',
            
            # HTML pages without database interaction
            r"<!DOCTYPE html>",
            r"<html>",
            r"<head>",
            r"<body>",
            r"</html>",
            
            # Static content indicators
            r"Welcome to",
            r"Page not found",
            r"404 Not Found",
            r"Access Denied",
            r"Unauthorized",
            
            # API testing services
            r"httpbin\.org",
            r"JSONPlaceholder",
            r"reqres\.in",
            r"mocky\.io",
        ]
        
        # Compile regex patterns for performance
        self.compiled_sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_error_patterns]
        self.compiled_non_db_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.non_database_patterns]
    
    def detect_sql_errors(self, response_text: str) -> bool:
        """
        Detect SQL errors in response text
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            bool: True if SQL errors detected
        """
        for pattern in self.compiled_sql_patterns:
            if pattern.search(response_text):
                return True
        return False
    
    def detect_non_database_response(self, response_text: str) -> bool:
        """
        Detect if response is from non-database endpoint (false positive)
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            bool: True if likely non-database endpoint
        """
        for pattern in self.compiled_non_db_patterns:
            if pattern.search(response_text):
                return True
        return False
    
    def analyze_response_differences(self, normal_response: str, injected_response: str) -> Dict:
        """
        Analyze differences between normal and injected responses
        
        Args:
            normal_response (str): Response without payload
            injected_response (str): Response with payload
            
        Returns:
            dict: Analysis results
        """
        normal_length = len(normal_response)
        injected_length = len(injected_response)
        length_difference = abs(normal_length - injected_length)
        
        # Calculate percentage difference
        if normal_length > 0:
            length_diff_percentage = (length_difference / normal_length) * 100
        else:
            length_diff_percentage = 0
        
        # Check for significant content changes
        content_similarity = self._calculate_similarity(normal_response, injected_response)
        
        # Detect database interaction
        has_sql_errors = self.detect_sql_errors(injected_response)
        is_non_database = self.detect_non_database_response(injected_response)
        
        return {
            "normal_length": normal_length,
            "injected_length": injected_length,
            "length_difference": length_difference,
            "length_diff_percentage": length_diff_percentage,
            "content_similarity": content_similarity,
            "sql_errors": has_sql_errors,
            "non_database_indicators": is_non_database
        }
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two texts
        
        Args:
            text1 (str): First text
            text2 (str): Second text
            
        Returns:
            float: Similarity percentage (0-100)
        """
        if not text1 and not text2:
            return 100.0
        
        if not text1 or not text2:
            return 0.0
        
        # Simple character-based similarity
        common_chars = 0
        max_length = max(len(text1), len(text2))
        
        for i in range(min(len(text1), len(text2))):
            if text1[i] == text2[i]:
                common_chars += 1
        
        return (common_chars / max_length) * 100
    
    def determine_vulnerability(self, analysis: Dict) -> Tuple[str, str]:
        """
        Determine vulnerability status with false positive detection
        
        Args:
            analysis (dict): Response analysis results
            
        Returns:
            tuple: (status, reason)
        """
        # CRITICAL: Check for false positives first
        if analysis["non_database_indicators"] and not analysis["sql_errors"]:
            return "FALSE_POSITIVE", "Non-database endpoint detected - response differences are normal"
        
        # High confidence: SQL errors detected
        if analysis["sql_errors"]:
            return "VULNERABLE", "SQL errors detected in response"
        
        # Medium confidence: Significant response changes
        if analysis["length_diff_percentage"] > 50:
            return "POSSIBLY_VULNERABLE", f"Significant response length change ({analysis['length_diff_percentage']:.1f}%)"
        
        if analysis["content_similarity"] < 30:
            return "POSSIBLY_VULNERABLE", f"Low content similarity ({analysis['content_similarity']:.1f}%)"
        
        # Low confidence: Moderate changes
        if analysis["length_diff_percentage"] > 20:
            return "POSSIBLY_VULNERABLE", f"Moderate response length change ({analysis['length_diff_percentage']:.1f}%)"
        
        return "SAFE", "No significant anomalies detected"
    
    def scan_responses(self, normal_response: str, injected_responses: List[str]) -> List[Dict]:
        """
        Scan multiple injected responses against normal response
        
        Args:
            normal_response (str): Baseline response
            injected_responses (list): List of responses with payloads
            
        Returns:
            list: List of scan results
        """
        results = []
        
        for i, injected_response in enumerate(injected_responses):
            analysis = self.analyze_response_differences(normal_response, injected_response)
            status, reason = self.determine_vulnerability(analysis)
            
            results.append({
                "payload_index": i,
                "analysis": analysis,
                "status": status,
                "reason": reason
            })
        
        return results
