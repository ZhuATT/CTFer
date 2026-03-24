"""侦察Agent: Web指纹识别
=======================
识别Web应用类型、框架、CMS等
"""

import requests
import re
from pathlib import Path
from typing import Dict, List, Any
from .. import ReconAgent, AgentResult


class WebFingerprintAgent(ReconAgent):
    """Web指纹识别Agent

    检测Web应用的框架、CMS、技术栈等
    """

    #指纹识别规则库
    FINGERPRINT_RULES = {
        "WordPress": {
            "patterns": ["/wp-content/", "wp-includes", "wordpress"],
            "headers": ["X-Powered-By: WordPress"],
            "meta": ["WordPress"]
        },
        "ThinkPHP": {
            "patterns": ["thinkphp", "/think", "Tp5"],
            "headers": [],
            "meta": ["ThinkPHP"]
        },
        "Django": {
            "patterns": ["csrftoken", "__debug__", "/admin/"],
            "headers": ["csrftoken"],
            "meta": []
        },
        "Flask": {
            "patterns": ["werkzeug", "flask"],
            "headers": ["Werkzeug"],
            "meta": []
        },
        "PHP": {
            "patterns": [".php?", "X-Powered-By: PHP"],
            "headers": ["X-Powered-By: PHP"],
            "meta": []
        },
        "AspNet": {
            "patterns": ["__VIEWSTATE", "ASP.NET"],
            "headers": ["X-AspNet-Version"],
            "meta": []
        },
        "Nginx": {
            "patterns": [],
            "headers": ["Server: nginx"],
            "meta": []
        },
        "Apache": {
            "patterns": [],
            "headers": ["Server: Apache"],
            "meta": []
        }
    }

    async def execute(self, target: str, **kwargs) -> AgentResult:
        """执行指纹识别

        Args:
            target: 目标URL
            **kwargs:
                timeout: 请求超时时间
                extra_paths: 额外探测路径列表
        """
        timeout = kwargs.get('timeout', 10)
        extra_paths = kwargs.get('extra_paths', ['/robots.txt', '/.git/HEAD', '/.env'])

        detected = []
        headers = {}
        responses = {}

        try:
            # 主页面请求
            resp = requests.get(target, timeout=timeout, verify=False, allow_redirects=True)
            responses['main'] = {
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'content': resp.text[:2000],
                'url': resp.url
            }

            content = resp.text
            response_headers = str(resp.headers)

            # 指纹识别
            for name, rules in self.FINGERPRINT_RULES.items():
                found = False

                # 检查内容特征
                for pattern in rules['patterns']:
                    if pattern.lower() in content.lower():
                        detected.append(f"{name}: found pattern '{pattern}'")
                        found = True
                        break

                # 检查响应头
                if not found:
                    for header_pattern in rules['headers']:
                        if header_pattern.lower() in response_headers.lower():
                            detected.append(f"{name}: header signature")
                            found = True
                            break

            # 探测额外路径
            found_special = []
            for path in extra_paths[:3]:  # 限制数量避免超时
                try:
                    test_url = target.rstrip('/') + path
                    r = requests.get(test_url, timeout=5, verify=False)
                    if r.status_code in [200, 301, 302, 403]:
                        found_special.append(f"{path}: HTTP {r.status_code}")
                except:
                    pass

            # 提取关键信息
            server_header = resp.headers.get('Server', 'Unknown')
            powered_by = resp.headers.get('X-Powered-By', 'Unknown')
            content_type = resp.headers.get('Content-Type', 'Unknown')

            findings = []
            if detected:
                findings.append(f"Fingerprints: {', '.join([d.split(':')[0] for d in detected])}")
            if found_special:
                findings.append(f"Special paths: {len(found_special)} interesting")
            findings.append(f"Server: {server_header}")

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=True,
                data={
                    "summary": f"Detected {len(detected)} fingerprints, {len(found_special)} special paths",
                    "detected_fingerprints": detected,
                    "server_header": server_header,
                    "x_powered_by": powered_by,
                    "content_type": content_type,
                    "interesting_paths": found_special,
                    "redirect_chain": responses['main'].get('url', target) if responses['main'].get('url') != target else None,
                    "findings": findings
                }
            )

        except Exception as e:
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                error=str(e),
                data={"summary": f"Fingerprint failed: {str(e)}"}
            )


