"""
长期记忆自动检索系统
========================

为Agent自动提供解题经验和POC

使用方法（Agent内部自动调用）:
    from long_memory import auto_memory

    # 1. Agent识别题目类型后自动加载相关资源
    resources = auto_memory.load_resources_for_type("lfi")

    # 2. Agent自动执行相关POC
    for poc in resources["pocs"]:
        result = poc.check_vulnerable(target_url)
        if result["vulnerable"]:
            # 利用此CVE获取flag
            ...

    # 3. 解题完成后自动保存经验
    auto_memory.save_experience(
        problem_type="lfi",
        target="http://target.com",
        steps=[...],
        flag="flag{...}",
        key_techniques=["路径遍历绕过", "日志包含"]
    )
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from taxonomy import canonicalize_problem_type, problem_type_aliases, identify_problem_type as taxonomy_identify


class LongMemory:
    """长期记忆管理器 - Agent内部自动使用"""

    BASE_PATH = Path(__file__).parent / "long_memory"

    def __init__(self):
        self.cve_index = None
        self.exp_index = None
        self._load_indexes()

    def _load_indexes(self):
        """加载索引文件"""
        # CVE索引
        cve_idx_path = self.BASE_PATH / "cve_pocs" / "cve_index.json"
        if cve_idx_path.exists():
            with open(cve_idx_path, 'r', encoding='utf-8') as f:
                self.cve_index = json.load(f)
        else:
            self.cve_index = {"cves": {}, "category_map": {}}

        # 经验索引
        exp_idx_path = self.BASE_PATH / "auto_experiences" / "exp_index.json"
        if exp_idx_path.exists():
            with open(exp_idx_path, 'r', encoding='utf-8') as f:
                self.exp_index = json.load(f)
        else:
            self.exp_index = {"experiences": {}, "category_map": {}}

    def identify_problem_type(self, url: str = "", description: str = "",
                               hint: str = "", initial_response: str = "") -> List[str]:
        """
        自动识别题目类型（委托给 taxonomy.identify_problem_type 统一入口）

        Args:
            url: 目标URL
            description: 题目描述
            hint: 提示信息
            initial_response: 初始页面响应

        Returns:
            可能的类型列表（按置信度排序）
        """
        return taxonomy_identify(url, description, hint, initial_response)

    def load_resources_for_type(self, problem_type: str) -> Dict[str, Any]:
        """
        加载指定类型的所有资源

        Args:
            problem_type: 题目类型 (sqli, lfi, rce, ...)

        Returns:
            {"pocs": [], "experiences": [], "tips": ""}
        """
        resources = {
            "canonical_problem_type": canonicalize_problem_type(problem_type),
            "type_aliases": problem_type_aliases(problem_type),
            "pocs": [],
            "experiences": [],
            "tips": "",
            "cve_list": []
        }

        canonical_type = resources["canonical_problem_type"]

        # 1. 加载CVE POC
        resources["cve_list"] = self.find_pocs_by_type(canonical_type)
        for cve_info in resources["cve_list"]:
            poc_path = self.BASE_PATH / "cve_pocs" / cve_info["file_path"]
            if poc_path.exists():
                with open(poc_path, 'r', encoding='utf-8') as f:
                    resources["pocs"].append({
                        "cve": cve_info["cve"],
                        "description": cve_info.get("description", ""),
                        "severity": cve_info.get("severity", "unknown"),
                        "code": f.read(),
                        "path": str(poc_path)
                    })

        # 2. 加载经验
        resources["experiences"] = self.load_experiences_by_type(canonical_type)

        # 3. 生成建议
        resources["tips"] = self._generate_tips(canonical_type, resources)

        return resources

    def find_pocs_by_type(self, prob_type: str) -> List[Dict]:
        """查找某类型的所有CVE POC"""
        results = []
        if not self.cve_index or "cves" not in self.cve_index:
            return results

        for cve_id, info in self.cve_index["cves"].items():
            if info.get("category") == prob_type:
                info["cve"] = cve_id
                results.append(info)

        return results

    def find_pocs_by_keywords(self, *keywords: str) -> List[Dict]:
        """按关键词查找CVE POC"""
        results = []
        text_keywords = [k.lower() for k in keywords]

        for cve_id, info in self.cve_index.get("cves", {}).items():
            searchable = f"{info.get('description', '')} {' '.join(info.get('keywords', []))}"
            searchable = searchable.lower()

            match_score = sum(1 for kw in text_keywords if kw in searchable)
            if match_score > 0:
                info["cve"] = cve_id
                info["match_score"] = match_score
                results.append(info)

        return sorted(results, key=lambda x: x["match_score"], reverse=True)

    def load_experiences_by_type(self, prob_type: str) -> List[Dict]:
        """加载某类型的解题经验"""
        results = []
        exp_dir = self.BASE_PATH / "auto_experiences" / prob_type

        if exp_dir.exists():
            for exp_file in sorted(exp_dir.glob("*.md"), reverse=True):
                # 最新的经验在前面
                content = exp_file.read_text(encoding="utf-8")
                results.append({
                    "file": exp_file.name,
                    "content": content,
                    "date": exp_file.stem[:10]  # 假设文件名以日期开头
                })

        return results

    def save_experience(self, problem_type: str, target: str = "",
                        steps: List[Dict] = None, flag: str = "",
                        key_techniques: List[str] = None,
                        lessons: str = "") -> str:
        """
        解题完成后自动保存经验

        Args:
            problem_type: 题目类型
            target: 目标URL/标识
            steps: 解题步骤列表
            flag: 获得的flag
            key_techniques: 使用的关键技术
            lessons: 经验教训

        Returns:
            保存的文件路径
        """
        problem_type = canonicalize_problem_type(problem_type)
        # 创建目录
        exp_dir = self.BASE_PATH / "auto_experiences" / problem_type
        exp_dir.mkdir(parents=True, exist_ok=True)

        # 生成文件名
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{date_str}_{self._slugify(target)}.md"

        # 构建Markdown内容
        techniques_md = "".join(f"- {t}\n" for t in (key_techniques or []))
        content = f"""# 解题经验: {problem_type}

## 基本信息
- **日期**: {datetime.now().isoformat()}
- **题目类型**: {problem_type}
- **目标**: {target}
- **Flag**: {flag if flag else "未记录"}

## 关键技术
{techniques_md}

## 解题步骤
"""
        # 添加步骤
        if steps:
            for i, step in enumerate(steps, 1):
                content += f"""### 步骤 {i}: {step.get('tool', 'unknown')}
- **目标**: {step.get('target', 'N/A')}
- **结果**: {'成功' if step.get('success') else '失败'}
- **详情**: {step.get('result', 'N/A')[:200]}...

"""

        # 添加经验教训
        if lessons:
            content += f"\n## 经验教训\n{lessons}\n"

        # 保存
        exp_file = exp_dir / filename
        exp_file.write_text(content, encoding="utf-8")

        # 更新索引
        self._update_exp_index(problem_type, filename, target)
        return str(exp_file)

    def _infer_framework(self, steps: list, prob_type: str) -> str:
        all_results = ' '.join([s.get('result', '') for s in steps]).lower()

        frameworks = {
            'Tornado': ['tornado', 'render', 'handler', 'application'],
            'Flask': ['flask', 'jinja2', 'request', 'session'],
            'Django': ['django', 'csrf', 'template'],
            'Spring': ['spring', 'java', 'thymeleaf'],
            'PHP': ['php', '<?php'],
        }

        for fw, keywords in frameworks.items():
            if any(k in all_results for k in keywords):
                return f'{fw}(Python)' if fw != 'PHP' else fw

        return f'{prob_type.upper()}(General)'

    def generate_report(self, problem_type: str, target: str, steps: list, flag: str) -> str:
        framework = self._infer_framework(steps, problem_type)
        
        findings = []
        for i, step in enumerate(steps, 1):
            tool = step.get('tool', 'unknown')
            step_target = step.get('target', '')
            result = step.get('result', '')
            
            if 'url' in step_target.lower() or 'http' in step_target.lower():
                findings.append(str(i) + '. ' + tool + ': ' + step_target)
            elif result and len(result) > 5:
                key_info = result[:100].replace(chr(10), ' ')
                findings.append(str(i) + '. ' + tool + ': ' + key_info + '...')
        
        target_name = target.split('/')[-1] if target else 'unknown'
        report = []
        report.append('=' * 80)
        report.append(' Solution Report')
        report.append('=' * 80)
        report.append('Target: ' + target_name)
        report.append('Vuln Type: ' + problem_type.upper())
        report.append('Framework: ' + framework)
        report.append('')
        report.append('Solution Steps')
        report.append('-' * 80)
        report.extend(findings)
        report.append('-' * 80)
        report.append('Flag: ' + flag)
        report.append('=' * 80)
        
        return chr(10).join(report)


    def _generate_tips(self, prob_type: str, resources: Dict) -> str:
        """生成操作建议"""
        tips = []
        cve_count = len(resources.get("cve_list", []))
        exp_count = len(resources.get("experiences", []))

        if cve_count > 0:
            tips.append(f"发现 {cve_count} 个相关CVE POC可以使用")
        if exp_count > 0:
            tips.append(f"有 {exp_count} 条历史经验可参考")

        # 类型特定建议
        specific_tips = {
            "sqli": ["先测试单引号触发错误", "使用sqlmap自动化扫描", "尝试union select"],
            "lfi": ["测试 ../../../etc/passwd", "尝试php://filter伪协议", "检查日志包含"],
            "rce": ["检查eval/assert等危险函数", "尝试命令拼接", "注意空格和特殊字符绕过"],
            "ssrf": ["测试file://协议读本地文件", "尝试gopher://攻击内网服务"],
            "xss": ["测试<script>alert(1)</script>", "尝试事件处理器", "注意CSP绕过"],
        }

        if prob_type in specific_tips:
            tips.extend(specific_tips[prob_type])

        return "\\n".join([f"- {t}" for t in tips])

    def _slugify(self, text: str) -> str:
        """将文本转为文件安全格式"""
        text = re.sub(r'[^\\w\\s-]', '', text)
        text = re.sub(r'[-\\s]+', '-', text)
        return text[:50] or "untitled"

    def _update_exp_index(self, prob_type: str, filename: str, target: str):
        """更新经验索引"""
        exp_idx_path = self.BASE_PATH / "auto_experiences" / "exp_index.json"

        index = {"experiences": {}, "category_map": {}}
        if exp_idx_path.exists():
            with open(exp_idx_path, 'r', encoding='utf-8') as f:
                index = json.load(f)

        if prob_type not in index["experiences"]:
            index["experiences"][prob_type] = []

        index["experiences"][prob_type].append({
            "file": filename,
            "target": target,
            "date": datetime.now().isoformat()
        })

        with open(exp_idx_path, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2, ensure_ascii=False)


# 单例实例
auto_memory = LongMemory()


# === 便捷函数 (Agent内部自动调用) ===

def auto_identify_and_load(url: str = "", description: str = "",
                              hint: str = "", initial_response: str = "") -> Dict[str, Any]:
    """
    自动识别题目类型并加载资源
    - Agent在 init_problem() 后调用此函数
    - 根据题目描述自动判断类型
    - 返回相关POC和经验
    """
    problem_types = auto_memory.identify_problem_type(url, description, hint, initial_response)

    results = {}
    for prob_type in problem_types[:2]:  # 取前两个可能的类型
        results[prob_type] = auto_memory.load_resources_for_type(prob_type)

    return {
        "probable_types": problem_types,
        "resources": results
    }


def auto_save_experience(problem_type: str, target: str = "",
                         steps: List[Dict] = None, flag: str = "",
                         key_techniques: List[str] = None) -> str:
    """
    解题完成后自动保存经验
    - Agent在获得flag后调用
    """
    return auto_memory.save_experience(
        problem_type=problem_type,
        target=target,
        steps=steps,
        flag=flag,
        key_techniques=key_techniques
    )


def find_pocs_by_type(prob_type: str) -> List[Dict]:
    """按类型查找POC"""
    return auto_memory.find_pocs_by_type(prob_type)


def find_pocs_by_keywords(*keywords: str) -> List[Dict]:
    """按关键词查找POC"""
    return auto_memory.find_pocs_by_keywords(*keywords)


# 导出
__all__ = [
    "auto_memory",
    "auto_identify_and_load",
    "auto_save_experience",
    "find_pocs_by_type",
    "find_pocs_by_keywords",
]
