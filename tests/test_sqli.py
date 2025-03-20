"""
SQL注入扫描器测试用例
"""
from src.scanners.sqli import SQLiScanner

def test_boolean_based():
    """测试布尔盲注检测"""
    scanner = SQLiScanner("http://testphp.vulnweb.com/search.php")
    scanner.scan_parameter('searchFor')
    assert len(scanner.results) > 0, "应检测到SQLi漏洞"

def test_time_based():
    """测试时间盲注检测"""
    scanner = SQLiScanner("http://testphp.vulnweb.com/listproducts.php")
    scanner.test_time_based('cat')
    assert any('Time-Based' in r['type'] for r in scanner.results), "应检测到时间盲注"