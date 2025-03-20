"""
主程序入口 - 演示扫描器使用
"""
from scanners.sqli import SQLiScanner

if __name__ == '__main__':
    # 目标测试URL（DVWA示例）
    target_url = "http://192.168.220.151/sqli/Less-6/?id=2"
    test_param = 'id'
    test_value='2'

    # 初始化扫描器
    scanner = SQLiScanner(target_url)

    # 执行扫描
    print(f"[*] 开始扫描 {target_url}")
    scanner.scan_parameter(test_param,test_value)

    # 输出结果
    print("\n[+] 扫描结果汇总:")
    for result in scanner.results:
        print(f"类型: {result['type']}")
        print(f"参数: {result['details']['param']}")
        print(f"Payload: {result['details']['payload']}")
        print("-" * 50)


