"""
SQL注入检测模块 - 支持布尔盲注和时间盲注
"""
import json
import time
from typing import Optional, Dict

import requests

from src.core.base_scanner import BaseScanner

class SQLiScanner(BaseScanner):
    def __init__(self, target_url: str, config_path: str = '../config/config.json'):
        super().__init__(target_url, config_path)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> Dict:
        """加载SQL注入payload"""
        try:
            with open('../config/payloads/sqli.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("[!] SQLi payload文件未找到")
            return {'boolean': [], 'time_based': []}

    def scan_parameter(self, param_name: str, test_value: str = '1'):
        """
        执行完整的SQL注入扫描流程

        :param param_name: 待测试参数名
        :param test_value: 基准测试值
        """
        if not self.config['sqli']['enable']:
            return

        # 执行布尔盲注检测
        self.test_boolean_based(param_name, test_value)
        # 执行时间盲注检测
        self.test_time_based(param_name)

    def test_boolean_based(self, param_name: str, test_value: str):
        """
        布尔盲注检测

        实现原理：
        1. 发送原始参数建立基准响应
        2. 发送真/假条件payload
        3. 使用响应相似度算法判断差异

        :param param_name: 参数名称
        :param test_value: 基准测试值
        """
        # 获取基准响应
        baseline = self.send_request({param_name: test_value})
        if not baseline:
            return

        # 遍历所有布尔payload
        for payload in self.payloads['boolean']:
            true_payload = test_value + payload
            false_payload = test_value + payload.replace("1", "0", 1)
            print(true_payload,'\n',false_payload)

            # 发送测试请求
            true_resp = self.send_request({param_name: true_payload})
            false_resp = self.send_request({param_name: false_payload})

            # 综合多维度分析
            if self._analyze_responses_enhanced(baseline, true_resp, false_resp):
                self.record_vulnerability(
                    'SQL Injection (Boolean)',
                    {
                        'param': param_name,
                        'payload': true_payload,
                        'technique': 'Boolean-based blind'

                    }
                )

    def _analyze_responses_enhanced(self, baseline: requests.Response,
                           true_resp: Optional[requests.Response],
                           false_resp: Optional[requests.Response]) -> bool:
        """
        优化版响应差异分析（四维判断法）

        改进点：
        1. 增加状态码验证
        2. 引入关键内容匹配
        3. 动态调整阈值
        4. 空值安全处理
        """
        # 空响应安全检查
        if not (true_resp and false_resp):
            return False

        # 维度1：响应长度差异（动态阈值）
        base_len = max(len(baseline.text), 1)  # 防止除零
        len_condition = (
                abs(len(true_resp.text) - base_len) / base_len < 0.1 and  # 真条件差异<20%
                abs(len(false_resp.text) - base_len) / base_len > 0  # 假条件差异>50%
        )

        # 维度2：状态码验证（真条件保持200，假条件可能不同）
    #    status_condition = (
     #           true_resp.status_code == baseline.status_code == 200 and
      #          false_resp.status_code != 200
       # )



        # 维度4：错误关键词检测（常见数据库错误特征）
        error_keywords = ["SQL syntax", "Database", "mysql_fetch"]
        error_condition = any(
            keyword in false_resp.text
            for keyword in error_keywords
        )

        # 综合判断（满足任意两个条件即视为存在漏洞）
        conditions_met = sum([
            len_condition,
           # status_condition,
            error_condition
        ])

        return conditions_met >= 1

    def test_time_based(self, param_name: str, delay: int = 5):
        """
        时间盲注检测

        :param param_name: 参数名称
        :param delay: 注入延迟时间（秒）
        """
        for payload in self.payloads['time_based']:
            start_time = time.time()
            self.send_request({param_name: payload})
            elapsed = time.time() - start_time

            # 考虑网络延迟误差
            if elapsed >= delay - 0.5:
                self.record_vulnerability(
                    'SQL Injection (Time-Based)',
                    {
                        'param': param_name,
                        'payload': payload,
                        'observed_delay': f"{elapsed:.2f}s"
                    }
                )