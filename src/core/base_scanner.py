"""
漏洞扫描器基类 - 提供通用功能
"""
import json
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

class BaseScanner:
    def __init__(self, target_url: str, config_path: str = '../config/config.json'):
        """
        初始化扫描器实例

        :param target_url: 目标URL地址
        :param config_path: 配置文件路径
        """
        self.target_url = self._normalize_url(target_url)
        self.config = self._load_config(config_path)
        self.session = requests.Session()
        self.results: List[dict] = []

        # 配置HTTP请求头
        self.session.headers.update(self.config['http']['headers'])

    def _normalize_url(self, url: str) -> str:
        """统一URL格式（添加协议前缀）"""
        if not urlparse(url).scheme:
            return f'http://{url}'
        return url

    def _load_config(self, config_path: str) -> Dict:
        """加载JSON配置文件"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"配置文件 {config_path} 不存在")

    def send_request(self, params: Dict, method: str = 'GET') -> Optional[requests.Response]:
        """
        发送HTTP请求

        :param params: 请求参数字典
        :param method: HTTP方法 (GET/POST)
        :return: Response对象或None
        """
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    self.target_url,
                    params=params,
                    timeout=self.config['http']['timeout']
                )
            else:
                response = self.session.post(
                    self.target_url,
                    data=params,
                    timeout=self.config['http']['timeout']
                )
            return response
        except requests.RequestException as e:
            print(f"[!] 请求失败: {str(e)}")
            return None

    def record_vulnerability(self, vuln_type: str, details: Dict):
        """
        统一记录漏洞信息

        :param vuln_type: 漏洞类型
        :param details: 漏洞详细信息
        """
        entry = {
            'type': vuln_type,
            'url': self.target_url,
            'details': details
        }
        self.results.append(entry)
        print(f"[+] 发现 {vuln_type} 漏洞 - 参数: {details.get('param')}")