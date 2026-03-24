"""侦察Agent: 目录爆破
==================
快速发现隐藏目录和文件
"""

import requests
import asyncio
from typing import Dict, List, Any, Tuple
from .. import ReconAgent, AgentResult


class DirBruteAgent(ReconAgent):
    """目录爆破Agent

    使用常见字典快速扫描目录和文件
    适合CTF场景，使用精简字典
    """

    # CTF优化的小型字典
    DEFAULT_WORDLIST = [
        # 常见目录
        "admin", "backup", "upload", "uploads", "images", "media",
        "static", "assets", "api", "api/v1", "api/v2",
        "test", "dev", "develop", "debug", "phpmyadmin",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        "config", "configuration", "settings",
        "robots.txt", "sitemap.xml", "README.md",

        # 常见文件
        "index.php", "index.html", "index.jsp",
        "login.php", "login.html", "login.jsp",
        "config.php", "database.php", "db.php",
        "admin.php", "admin.html", "admin.jsp",
        "flag.php", "flag.txt", "flag",
        "shell.php", "webshell.php", "cmd.php",
        "wp-login.php", "wp-admin", "wp-content",
        "phpinfo.php", "phpmyadmin",
    ]

    EXTENSIONS = ["", ".php", ".html", ".txt", ".bak", ".old", ".zip", ".tar.gz"]

    def __init__(self, agent_id: str = None, max_concurrent: int = 10):
        super().__init__(agent_id)
        self.max_concurrent = max_concurrent
        self.found_paths = []

    async def execute(self, target: str, **kwargs) -> AgentResult:
        """执行目录爆破

        Args:
            target: 目标URL
            **kwargs:
                wordlist: 自定义字典
                extensions: 扩展名字典
                max_depth: 最大扫描深度
                timeout: 单请求超时
        """
        wordlist = kwargs.get('wordlist', self.DEFAULT_WORDLIST)
        extensions = kwargs.get('extensions', self.EXTENSIONS)
        timeout = kwargs.get('timeout', 5)
        max_total = kwargs.get('max_total', 100)  # 限制总请求数

        self.found_paths = []
        discovered = []
        tested = 0

        # 构建URL列表
        urls_to_test = []
        base = target.rstrip('/')

        for word in wordlist:
            for ext in extensions:
                url = f"{base}/{word}{ext}"
                urls_to_test.append(url)
                if len(urls_to_test) >= max_total:
                    break
            if len(urls_to_test) >= max_total:
                break

        # 限制并发扫描
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._test_url(url, semaphore, timeout) for url in urls_to_test]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple) and result[0]:  # (found, url, status)
                found, url, status = result
                if found:
                    discovered.append((url, status))
                    tested += 1

        tested = len([r for r in results if not isinstance(r, Exception)])

        # 构建findings
        findings = []
        interesting = []

        for url, status in discovered:
            path = url.split('/')[-1] if '/' in url else url

            if status == 200:
                if any(x in path.lower() for x in ['admin', 'login', 'backup', 'config', 'flag', '.git', '.env']):
                    interesting.append(f"[CRITICAL] {path} (HTTP 200)")
                else:
                    findings.append(f"{path} (HTTP 200)")
            elif status == 302:
                if any(x in path.lower() for x in ['admin', 'login']):
                    interesting.append(f"[REDIRECT] {path}")
            elif status == 403:
                findings.append(f"{path} (Forbidden)")

        all_findings = interesting + findings

        return AgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            success=True,
            data={
                "summary": f"Found {len(discovered)} paths from {tested} tested",
                "total_tested": tested,
                "found_count": len(discovered),
                "found_paths": discovered[:20],  # 限制返回数量
                "high_priority": interesting,
                "findings": all_findings[:10]  # 主Agent看到的摘要
            }
        )

    async def _test_url(self, url: str, semaphore: asyncio.Semaphore, timeout: int) -> Tuple[bool, str, int]:
        """测试单个URL

        Returns:
            (found, url, status_code)
        """
        async with semaphore:
            try:
                # 使用线程池执行同步requests
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    self._check_url_sync,
                    url,
                    timeout
                )
                return result
            except Exception as e:
                return (False, url, 0)

    def _check_url_sync(self, url: str, timeout: int) -> Tuple[bool, str, int]:
        """同步检查URL"""
        try:
            import requests
            requests.packages.urllib3.disable_warnings()

            resp = requests.head(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )

            if resp.status_code in [200, 301, 302, 303, 307, 308, 403]:
                # 对于HEAD请求成功但不确定的，用GET验证
                if resp.status_code == 200:
                    try:
                        get_resp = requests.get(url, timeout=timeout, verify=False, stream=True)
                        get_resp.close()

                        # 排除常见的404伪装
                        if get_resp.status_code == 200 and len(get_resp.text) > 0:
                            return (True, url, 200)
                    except:
                        pass

                return (True, url, resp.status_code)

            return (False, url, resp.status_code)
        except:
            return (False, url, 0)


