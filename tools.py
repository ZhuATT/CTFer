"""
CTF Agent 工具集 - v2.0 集成双记忆系统
======================================

设计方案：
- 短期记忆：单题防重复、记步骤、自动提取关键信息
- 长期记忆：经验累积、POC复用、解题技巧（手动管理）
- 全自动解题：Claude自主决策，遇到困难才求助

使用：
    from tools import *
    reset_memory()  # 开始新题目

    # 自动记录和执行
    result = execute_command("...")
"""

import os
import re
import json
import subprocess
import warnings
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

from toolkit.base import get_venv_python, run_subprocess
from taxonomy import KEYWORD_HINTS, build_taxonomy_profile, canonical_skill_names, canonicalize_problem_type, problem_type_aliases, taxonomy_findings_from_profile

# 导入短期记忆
from short_memory import get_short_memory, reset_short_memory, ShortMemory, AgentContext, extract_flag_candidates, classify_generic_findings

# 导入长期记忆系统
try:
    from long_memory import auto_identify_and_load, auto_save_experience
    LONG_MEMORY_AVAILABLE = True
except ImportError:
    LONG_MEMORY_AVAILABLE = False
    auto_identify_and_load = auto_save_experience = None

# 导入多智能体系统
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from agents.coordination import ReconCoordinator, run_recon_sync
    MULTI_AGENT_AVAILABLE = True
except ImportError as e:
    MULTI_AGENT_AVAILABLE = False
    ReconCoordinator = None
    run_recon_sync = None
    print(f"[Warn] Multi-agent system not available: {e}")

try:
    from toolkit.sqlmap import scan as sqlmap_scan, deep_scan as sqlmap_deep_scan
    from toolkit.dirsearch import scan as dirsearch_scan, quick_scan as dirsearch_quick_scan
    TOOLKIT_AVAILABLE = True
except ImportError:
    TOOLKIT_AVAILABLE = False
    sqlmap_scan = sqlmap_deep_scan = dirsearch_scan = dirsearch_quick_scan = None

# 全局记忆实例
_short_memory_instance: Optional[ShortMemory] = None


def get_memory() -> ShortMemory:
    """获取当前短期记忆实例"""
    global _short_memory_instance
    if _short_memory_instance is None:
        _short_memory_instance = get_short_memory()
    return _short_memory_instance


def get_agent_context() -> AgentContext:
    """获取当前题目的初始化上下文"""
    memory = get_memory()
    return memory.get_context()
def reset_memory():
    """开始新题目时重置记忆"""
    global _short_memory_instance
    reset_short_memory()
    _short_memory_instance = get_short_memory()


def _load_llm_config() -> dict:
    """从 config.json 加载 LLM 配置"""
    from pathlib import Path
    config_path = Path(__file__).parent / "config.json"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            return cfg.get("llm", {})
        except (json.JSONDecodeError, IOError):
            pass
    return {}

_LLM_CONFIG = _load_llm_config()


def _classify_problem_with_llm(target_url: str, description: str = "", hint: str = "", initial_response: str = "") -> Dict[str, Any]:
    """LLM-first classifier. If no model client/config is available, return unavailable and let heuristic fallback."""
    cfg = _LLM_CONFIG

    # api_key: 环境变量 > config.json
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or cfg.get("api_key", "").strip()
    # api_base: 环境变量 > config.json
    api_base = os.environ.get("ANTHROPIC_BASE_URL", "").strip() or cfg.get("api_base", "").strip()
    # model: 环境变量 > config.json
    model_name = os.environ.get("ANTHROPIC_MODEL", "").strip() or cfg.get("model", "").strip()

    prompt_payload = {
        "url": target_url,
        "description": description[:1200],
        "hint": hint[:1200],
        "initial_response_excerpt": initial_response[:4000],
        "allowed_problem_types": sorted({canonicalize_problem_type(name) for name in KEYWORD_HINTS.keys()} | {"unknown"}),
    }

    if not model_name and not api_base:
        return {
            "problem_type": "unknown",
            "confidence": 0.0,
            "source": "llm-unavailable",
            "reasoning_summary": "未配置分类模型，退回 heuristic",
            "evidence": [],
        }

    try:
        if api_base:
            response = requests.post(
                api_base.rstrip("/") + "/classify",
                json=prompt_payload,
                headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                timeout=20,
                verify=False,
            )
            response.raise_for_status()
            payload = dict(response.json() or {})
        else:
            payload = {}
            try:
                from anthropic import Anthropic
            except Exception:
                return {
                    "problem_type": "unknown",
                    "confidence": 0.0,
                    "source": "llm-unavailable",
                    "reasoning_summary": "未安装可用模型客户端，退回 heuristic",
                    "evidence": [],
                }
            if not api_key:
                return {
                    "problem_type": "unknown",
                    "confidence": 0.0,
                    "source": "llm-unavailable",
                    "reasoning_summary": "缺少模型 API Key，退回 heuristic",
                    "evidence": [],
                }
            client = Anthropic(api_key=api_key)
            message = client.messages.create(
                model=model_name or "claude-sonnet-4-6",
                max_tokens=300,
                temperature=0,
                system="你是 CTF Web 题型分类器。只能输出 JSON。problem_type 必须来自 allowed_problem_types，confidence 范围 0-1。",
                messages=[{
                    "role": "user",
                    "content": json.dumps(prompt_payload, ensure_ascii=False),
                }],
            )
            text = "".join(block.text for block in message.content if getattr(block, "type", "") == "text")
            payload = json.loads(text)

        problem_type = canonicalize_problem_type(payload.get("problem_type") or "unknown")
        confidence = max(0.0, min(1.0, float(payload.get("confidence") or 0.0)))
        evidence = list(payload.get("evidence") or [])[:8]
        reasoning = str(payload.get("reasoning_summary") or payload.get("reason") or "")
        return {
            "problem_type": problem_type,
            "confidence": confidence,
            "source": "llm",
            "reasoning_summary": reasoning or "模型已给出分类结论",
            "evidence": evidence,
        }
    except Exception as e:
        return {
            "problem_type": "unknown",
            "confidence": 0.0,
            "source": "llm-error",
            "reasoning_summary": f"模型分类失败，退回 heuristic: {e}",
            "evidence": [],
        }


    text = " ".join([target_url or "", description or "", hint or "", initial_response or ""]).lower()
    direct_hint_signals = {
        "phpinfo": any(token in text for token in ["phpinfo", "信息泄露", "配置泄露"]),
        "git_exposure": any(token in text for token in [".git", "git 泄露", "git泄露", "源码泄露", "目录扫描", "扫目录"]),
    }
    if direct_hint_signals["phpinfo"] or direct_hint_signals["git_exposure"]:
        return {
            "problem_type": "unknown",
            "confidence": 0.2,
            "source": "heuristic",
            "reasoning_summary": "高价值信息泄露信号优先，避免被通用漏洞关键词误判",
            "evidence": [name for name, matched in direct_hint_signals.items() if matched],
        }

    scores: Dict[str, int] = {}
    for ptype, keywords in KEYWORD_HINTS.items():
        score = sum(1 for keyword in keywords if keyword.lower() in text)
        if score > 0:
            scores[canonicalize_problem_type(ptype)] = max(score, scores.get(canonicalize_problem_type(ptype), 0))

    if not scores:
        return {
            "problem_type": "unknown",
            "confidence": 0.0,
            "source": "heuristic",
            "reasoning_summary": "未命中可靠关键词，保持 unknown",
            "evidence": [],
        }

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    problem_type, top_score = ranked[0]
    evidence = [keyword for keyword in KEYWORD_HINTS.get(problem_type, []) if keyword.lower() in text][:6]
    confidence = min(0.75, 0.25 + 0.1 * top_score)
    return {
        "problem_type": canonicalize_problem_type(problem_type),
        "confidence": confidence,
        "source": "heuristic",
        "reasoning_summary": f"命中 {top_score} 个 {problem_type} 相关关键词",
        "evidence": evidence,
    }



def _classify_problem_by_keywords(target_url: str, description: str = "", hint: str = "", initial_response: str = "") -> Dict[str, Any]:
    text = " ".join([target_url or "", description or "", hint or "", initial_response or ""]).lower()
    direct_hint_signals = {
        "phpinfo": any(token in text for token in ["phpinfo", "信息泄露", "配置泄露"]),
        "git_exposure": any(token in text for token in [".git", "git 泄露", "git泄露", "源码泄露", "目录扫描", "扫目录"]),
    }
    if direct_hint_signals["phpinfo"] or direct_hint_signals["git_exposure"]:
        return {
            "problem_type": "unknown",
            "confidence": 0.2,
            "source": "heuristic",
            "reasoning_summary": "高价值信息泄露信号优先，避免被通用漏洞关键词误判",
            "evidence": [name for name, matched in direct_hint_signals.items() if matched],
        }

    scores: Dict[str, int] = {}
    for ptype, keywords in KEYWORD_HINTS.items():
        score = sum(1 for keyword in keywords if keyword.lower() in text)
        if score > 0:
            canonical = canonicalize_problem_type(ptype)
            scores[canonical] = max(score, scores.get(canonical, 0))

    if not scores:
        return {
            "problem_type": "unknown",
            "confidence": 0.0,
            "source": "heuristic",
            "reasoning_summary": "未命中可靠关键词，保持 unknown",
            "evidence": [],
        }

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    problem_type, top_score = ranked[0]
    evidence = [keyword for keyword in KEYWORD_HINTS.get(problem_type, []) if keyword.lower() in text][:6]
    confidence = min(0.75, 0.25 + 0.1 * top_score)
    return {
        "problem_type": canonicalize_problem_type(problem_type),
        "confidence": confidence,
        "source": "heuristic",
        "reasoning_summary": f"命中 {top_score} 个 {problem_type} 相关关键词",
        "evidence": evidence,
    }


def init_problem(target_url: str, description: str = "", hint: str = "") -> Dict[str, Any]:
    """
    初始化题目并自动识别类型、加载资源
    """
    reset_memory()
    memory = get_memory()

    memory.update_target(url=target_url)
    memory.set_context(
        url=target_url,
        description=description,
        hint=hint,
    )

    initial_response_text = ""
    llm_result = _classify_problem_with_llm(target_url, description, hint)
    heuristic_result = _classify_problem_by_keywords(target_url, description, hint)
    selected_result = llm_result if str(llm_result.get("source") or "").startswith("llm") and float(llm_result.get("confidence") or 0.0) >= 0.45 else heuristic_result
    problem_type = canonicalize_problem_type(selected_result.get("problem_type") or "unknown")
    classification_confidence = float(selected_result.get("confidence") or 0.0)
    classification_source = str(selected_result.get("source") or "heuristic")
    classification_evidence = list(selected_result.get("evidence") or [])
    classification_reasoning = str(selected_result.get("reasoning_summary") or "")

    if target_url:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                resp = requests.get(target_url, timeout=10, verify=False)
            initial_response_text = resp.text or ""
            page_content = initial_response_text.lower()
            page_heuristic = _classify_problem_by_keywords(target_url, description, hint, page_content[:4000])
            page_type = canonicalize_problem_type(page_heuristic.get("problem_type") or "unknown")
            page_confidence = float(page_heuristic.get("confidence") or 0.0)

            if "phpinfo()" in page_content or ("php version" in page_content and "php credits" in page_content):
                print("[Auto-detect] 页面特征命中 phpinfo，标记为信息泄露场景")
                memory.add_step(
                    tool="init_probe",
                    target=target_url,
                    params={},
                    result="phpinfo exposed",
                    success=True,
                    key_findings=["phpinfo_exposed", "info_leak"],
                )
                problem_type = "unknown"
                classification_confidence = 0.2
                classification_source = "heuristic"
                classification_evidence = ["phpinfo", "info_leak"]
                classification_reasoning = "页面命中 phpinfo / 信息泄露特征，抑制泛化关键词误判"
            elif page_confidence > classification_confidence:
                problem_type = page_type
                classification_confidence = page_confidence
                classification_source = str(page_heuristic.get("source") or "heuristic")
                classification_evidence = list(page_heuristic.get("evidence") or [])
                classification_reasoning = str(page_heuristic.get("reasoning_summary") or "")
                if problem_type != "unknown":
                    print(f"[Auto-detect] 从页面内容识别出类型: {problem_type}")

            server = resp.headers.get("Server", "").lower()
            if "tornado" in server:
                problem_type = "tornado"
                classification_confidence = max(classification_confidence, 0.8)
                classification_source = "heuristic"
                classification_evidence = list(dict.fromkeys(classification_evidence + ["server:tornado"]))
                classification_reasoning = "Server header 明确暴露 tornado"
                print("[Auto-detect] 从Server header识别出类型: tornado")
        except Exception as e:
            print(f"[Auto-detect] 访问目标失败: {e}")

    problem_type = canonicalize_problem_type(problem_type)
    taxonomy_profile = build_taxonomy_profile(problem_type, target_url, description, hint, initial_response_text[:4000])
    resource_bundle = _assemble_resource_bundle(
        taxonomy_profile,
        target_url=target_url,
        description=description,
        hint=hint,
        initial_response=initial_response_text[:4000],
    )
    skill_content = str(resource_bundle.get("skill_content") or "")
    if skill_content:
        primary_skill = (resource_bundle.get("skills") or ["unknown"])[0]
        print(f"\n>>> Skills知识库 [{primary_skill}]:")
        print("-" * 40)
        lines = skill_content.split('\n')[:50]
        print('\n'.join(lines))
        if len(skill_content) > 2000:
            print(f"\n... [知识库内容过长，已截断，共{len(skill_content)}字符]")

    loaded_resources = {
        "taxonomy_profile": taxonomy_profile,
        "resource_bundle": resource_bundle,
        "source_breakdown": {
            "skills": list(resource_bundle.get("skills") or []),
            "long_memory_probable_types": list(resource_bundle.get("long_memory_probable_types") or []),
            "wooyun_seed_count": len(resource_bundle.get("wooyun_seed_knowledge") or []),
        },
        "probable_types": list(resource_bundle.get("long_memory_probable_types") or []),
        "resources": dict(resource_bundle.get("long_memory_resources") or {}),
    }

    if loaded_resources.get("probable_types"):
        print(f"\n>>> 识别类型: {loaded_resources['probable_types']}")
    for ptype, resources in loaded_resources.get("resources", {}).items():
        if resources.get("experiences"):
            print(f"\n>>> 历史经验 [{ptype}]: {len(resources['experiences'])} 条")
            for exp in resources["experiences"][:2]:
                print(f"    - {exp.get('file', 'unknown')}")
        if resources.get("pocs"):
            print(f"\n>>> CVE POC [{ptype}]: {len(resources['pocs'])} 个")
            for poc in resources["pocs"][:3]:
                print(f"    - {poc.get('cve', 'unknown')}: {poc.get('description', '')[:40]}")
        if resources.get("tips"):
            print(f"\n>>> 建议操作:")
            print(resources["tips"])

    wooyun_ref = str(resource_bundle.get("wooyun_ref") or "")
    if wooyun_ref:
        print(f"\n>>> WooYun知识:")
        print(wooyun_ref[:500])

    print(f"\n{'='*60}")
    print(f"[Problem Init Complete] Type: {problem_type}")
    print(f"{'='*60}\n")

    for finding in taxonomy_findings_from_profile(taxonomy_profile):
        current_shared = list(memory.context.shared_findings or [])
        current_shared.append(finding)
        memory.context.shared_findings = current_shared

    memory.set_context(
        url=target_url,
        description=description,
        hint=hint,
        problem_type=problem_type,
        skill_content=skill_content,
        loaded_resources=loaded_resources,
        wooyun_ref=wooyun_ref,
        classification_confidence=classification_confidence,
        classification_source=classification_source,
        classification_evidence=classification_evidence,
        classification_reasoning=classification_reasoning,
    )

    return {
        "target_url": target_url,
        "description": description,
        "hint": hint,
        "problem_type": problem_type,
        "skill_content": skill_content,
        "loaded_resources": loaded_resources,
        "wooyun_ref": wooyun_ref,
        "taxonomy_profile": taxonomy_profile,
        "classification_confidence": classification_confidence,
        "classification_source": classification_source,
        "classification_evidence": classification_evidence,
        "classification_reasoning": classification_reasoning,
    }
def _resolve_skill_resources(profile: Dict[str, Any]) -> Dict[str, Any]:
    canonical_type = canonicalize_problem_type(profile.get("canonical_problem_type") or "unknown")
    skill_names = []
    skill_content = ""
    for skill_name in profile.get("skill_names") or canonical_skill_names(canonical_type):
        skill_path = Path(__file__).parent / "skills" / skill_name / "SKILL.md"
        if not skill_path.exists():
            continue
        skill_names.append(skill_name)
        if not skill_content:
            skill_content = skill_path.read_text(encoding="utf-8")
    return {
        "skills": skill_names,
        "skill_content": skill_content,
    }


def _resolve_long_memory_resources(profile: Dict[str, Any], target_url: str = "", description: str = "", hint: str = "", initial_response: str = "") -> Dict[str, Any]:
    canonical_type = canonicalize_problem_type(profile.get("canonical_problem_type") or "unknown")
    result = {
        "probable_types": [canonical_type] if canonical_type != "unknown" else [],
        "resources": {},
        "experiences": [],
        "pocs": [],
        "tips": "",
    }
    if not LONG_MEMORY_AVAILABLE:
        return result
    try:
        from long_memory import auto_memory
        memory_resources = auto_memory.load_resources_for_type(canonical_type)
        result["resources"][canonical_type] = memory_resources
        result["experiences"] = list(memory_resources.get("experiences") or [])
        result["pocs"] = list(memory_resources.get("pocs") or [])
        result["tips"] = str(memory_resources.get("tips") or "")
        if canonical_type == "unknown" and auto_identify_and_load:
            auto_detected = auto_identify_and_load(url=target_url, description=description, hint=hint, initial_response=initial_response)
            result["probable_types"] = list(auto_detected.get("probable_types") or [])
            result["resources"].update(dict(auto_detected.get("resources") or {}))
    except Exception:
        pass
    return result


def _resolve_wooyun_resources(profile: Dict[str, Any], target_url: str = "", description: str = "", hint: str = "") -> Dict[str, Any]:
    canonical_type = canonicalize_problem_type(profile.get("canonical_problem_type") or "unknown")
    wooyun_ref = ""
    seed_knowledge = []
    if canonical_type == "unknown":
        return {"wooyun_ref": wooyun_ref, "wooyun_seed_knowledge": seed_knowledge}
    try:
        from skills.wooyun.wooyun_rag import retrieve_knowledge
        wooyun_context = retrieve_knowledge(
            query=f"{description} {hint}".strip() or canonical_type,
            context={
                "current_vuln_type": canonical_type,
                "target_url": target_url,
                "tech_stack": list(profile.get("framework_tags") or []),
                "attempted_methods": [],
                "problem_description": description,
                "taxonomy_aliases": list(profile.get("type_aliases") or []),
                "taxonomy_tags": list(profile.get("taxonomy_tags") or []),
            },
            top_k=3,
        )
        seed_knowledge = list(wooyun_context.get("retrieved_knowledge") or [])
        wooyun_ref = _format_wooyun_ref(wooyun_context)
    except Exception:
        pass
    return {"wooyun_ref": wooyun_ref, "wooyun_seed_knowledge": seed_knowledge}


def _assemble_resource_bundle(profile: Dict[str, Any], target_url: str = "", description: str = "", hint: str = "", initial_response: str = "") -> Dict[str, Any]:
    canonical_type = canonicalize_problem_type(profile.get("canonical_problem_type") or "unknown")
    aliases = list(profile.get("type_aliases") or problem_type_aliases(canonical_type))
    skill_resources = _resolve_skill_resources(profile)
    memory_resources = _resolve_long_memory_resources(
        profile,
        target_url=target_url,
        description=description,
        hint=hint,
        initial_response=initial_response,
    )
    wooyun_resources = _resolve_wooyun_resources(
        profile,
        target_url=target_url,
        description=description,
        hint=hint,
    )
    return {
        "canonical_problem_type": canonical_type,
        "type_aliases": aliases,
        "skills": list(skill_resources.get("skills") or []),
        "skill_content": str(skill_resources.get("skill_content") or ""),
        "experiences": list(memory_resources.get("experiences") or []),
        "pocs": list(memory_resources.get("pocs") or []),
        "wooyun_seed_knowledge": list(wooyun_resources.get("wooyun_seed_knowledge") or []),
        "taxonomy_tags": list(profile.get("taxonomy_tags") or []),
        "resource_hints": dict(profile.get("resource_hints") or {}),
        "long_memory_probable_types": list(memory_resources.get("probable_types") or []),
        "long_memory_resources": dict(memory_resources.get("resources") or {}),
        "long_memory_tips": str(memory_resources.get("tips") or ""),
        "wooyun_ref": str(wooyun_resources.get("wooyun_ref") or ""),
    }


def get_available_resources() -> Dict[str, Any]:
    """
    获取当前题目可用的资源（POC、经验、知识）
    Agent 可在任何时候调用查看可用资源
    """
    memory = get_memory()
    prob_type = canonicalize_problem_type(memory.target.problem_type or "unknown")
    target_url = memory.target.url or ""
    context = memory.get_context()
    loaded_resources = dict(getattr(context, "loaded_resources", {}) or {})
    taxonomy_profile = dict(loaded_resources.get("taxonomy_profile") or build_taxonomy_profile(prob_type, target_url, getattr(context, "description", ""), getattr(context, "hint", "")))
    resource_bundle = dict(loaded_resources.get("resource_bundle") or _assemble_resource_bundle(
        taxonomy_profile,
        target_url=target_url,
        description=getattr(context, "description", ""),
        hint=getattr(context, "hint", ""),
    ))

    result = {
        "problem_type": prob_type,
        "canonical_problem_type": taxonomy_profile.get("canonical_problem_type", prob_type),
        "target": target_url,
        "pocs": list(resource_bundle.get("pocs") or []),
        "experiences": list(resource_bundle.get("experiences") or []),
        "wooyun_knowledge": list(resource_bundle.get("wooyun_seed_knowledge") or []),
        "taxonomy_profile": taxonomy_profile,
        "resource_bundle": resource_bundle,
        "source_breakdown": dict(loaded_resources.get("source_breakdown") or {}),
    }

    # 打印摘要
    print(f"\n{'='*60}")
    print(f"[Available Resources] Type: {result['canonical_problem_type']}")
    print(f"{'='*60}")

    if result["pocs"]:
        print(f"\n>> CVE POC ({len(result['pocs'])}个):")
        for p in result["pocs"][:5]:
            print(f"   - {p.get('cve', 'unknown')}: {p.get('description', '')[:50]}")

    if result["experiences"]:
        print(f"\n>> 历史经验 ({len(result['experiences'])}条):")
        for e in result["experiences"][:3]:
            print(f"   - {e.get('file', 'unknown')}")

    if result["wooyun_knowledge"]:
        print(f"\n>> WooYun知识 ({len(result['wooyun_knowledge'])}条):")
        for k in result["wooyun_knowledge"]:
            print(f"   - [{k.get('type', '')}] {k.get('content', '')[:60]}...")

    print(f"{'='*60}\n")

    return result



def update_problem_type(problem_type: str) -> str:
    memory = get_memory()
    memory.update_target(problem_type=problem_type)
    print(f'[Update] 题目类型已更新为: {problem_type}')
    get_available_resources()
    return problem_type

# ===================== WooYun RAG Integration =====================

def _build_rag_query_context(
    query: str,
    vuln_type: str,
    target_url: str,
    attempted_methods: List[str],
) -> Dict[str, Any]:
    memory = get_memory()
    context = memory.get_context()
    description = getattr(context, "description", "")
    hint = getattr(context, "hint", "")
    loaded_resources = dict(getattr(context, "loaded_resources", {}) or {})
    taxonomy_profile = dict(loaded_resources.get("taxonomy_profile") or build_taxonomy_profile(vuln_type, target_url, description, hint))
    shared_findings = list(getattr(context, "shared_findings", []) or [])
    return {
        "current_vuln_type": canonicalize_problem_type(vuln_type or taxonomy_profile.get("canonical_problem_type") or "unknown"),
        "target_url": target_url or getattr(context, "url", ""),
        "tech_stack": list(taxonomy_profile.get("framework_tags") or []),
        "attempted_methods": list(attempted_methods or []),
        "problem_description": query,
        "taxonomy_aliases": list(taxonomy_profile.get("type_aliases") or []),
        "taxonomy_tags": list(taxonomy_profile.get("taxonomy_tags") or []),
        "shared_findings": shared_findings,
    }


def retrieve_rag_knowledge(query: str = "", vuln_type: str = "", target_url: str = "", attempted_methods: List[str] = None) -> Dict[str, Any]:
    """
    解题过程中主动检索 WooYun 知识库
    Agent 可在任何时候调用此函数获取相关知识

    Args:
        query: 当前问题描述，如"如何绕过WAF"
        vuln_type: 漏洞类型，如"sqli", "lfi", "rce"
        target_url: 目标URL
        attempted_methods: 已尝试的方法列表

    Returns:
        检索结果字典，包含:
        - retrieved_knowledge: 相关知识列表
        - suggested_approach: 建议做法
    """
    if attempted_methods is None:
        attempted_methods = []

    try:
        import sys
        from pathlib import Path
        rag_path = Path(__file__).parent / "skills" / "wooyun"
        if str(rag_path) not in sys.path:
            sys.path.insert(0, str(rag_path))

        from wooyun_rag import retrieve_knowledge as wooyun_retrieve

        context = _build_rag_query_context(query, vuln_type, target_url, attempted_methods)
        result = wooyun_retrieve(query=query, context=context, top_k=5)

        # 格式化输出
        if result.get("retrieved_knowledge"):
            print(f"\n{'='*60}")
            print(f"[RAG] 检索到 {len(result['retrieved_knowledge'])} 条相关知识")
            print(f"{'='*60}")

            for i, item in enumerate(result["retrieved_knowledge"], 1):
                item_type = item.get("type", "unknown")
                content = item.get("content", "")[:200]
                score = item.get("relevance_score", 0)
                print(f"{i}. [{item_type}] (相关性:{score}) {content}...")

            if result.get("suggested_approach"):
                print(f"\n>> 建议: {result['suggested_approach']}")
            print(f"{'='*60}\n")

        return result

    except Exception as e:
        return {"error": str(e), "retrieved_knowledge": [], "suggested_approach": ""}

def _format_wooyun_ref(wooyun_context: dict) -> str:
    """格式化WooYun检索结果"""
    if not wooyun_context or "retrieved_knowledge" not in wooyun_context:
        return ""
    
    lines = ["【WooYun真实案例参考】"]
    for i, item in enumerate(wooyun_context["retrieved_knowledge"], 1):
        item_type = item.get("type", "unknown")
        content = item.get("content", "")[:150]
        
        if item_type == "payload":
            lines.append(f"{i}. Payload样例: {content}...")
        elif item_type == "technique":
            lines.append(f"{i}. 攻击技术: {content}...")
        elif item_type == "case":
            lines.append(f"{i}. 类似案例: {content}...")
        elif item_type == "parameter":
            lines.append(f"{i}. 高频参数: {content}...")
    
    if wooyun_context.get("suggested_approach"):
        lines.append(f"建议做法: {wooyun_context['suggested_approach']}")
    
    return "  ".join(lines)

def _retrieve_wooyun_knowledge(primary_type: str, description: str, hint: str, target_url: str) -> str:
    """WooYun RAG: AI自动检索知识（集成在init_problem中）"""
    wooyun_ref = ""
    try:
        from skills.wooyun.wooyun_rag import retrieve_knowledge
        wooyun_context = retrieve_knowledge(
            query=f"{description} {hint}",
            context={
                "current_vuln_type": primary_type,
                "target_url": target_url,
                "tech_stack": [],
                "attempted_methods": [],
                "problem_description": description
            },
            top_k=3
        )
        wooyun_ref = _format_wooyun_ref(wooyun_context)
        if wooyun_ref:
            print(f"=== 【WooYun知识】AI自动加载 ===")
            print(wooyun_ref[:400])
    except Exception as e:
        print(f"[Agent] WooYun检索出错: {e}")
    return wooyun_ref

# ==================== 原函数的其余部分 ====================


# ==================== 内部工具函数 ====================

def _http_request_with_retry(method: str, url: str, max_retries: int = 3, 
                              backoff_factor: float = 1.0, **kwargs) -> requests.Response:
    """
    带重试机制的HTTP请求
    
    Args:
        method: GET/POST
        url: 目标URL
        max_retries: 最大重试次数
        backoff_factor: 重试间隔增长因子
        **kwargs: 传递给requests的参数
    
    Returns:
        Response对象
    """
    import time
    
    for attempt in range(max_retries):
        try:
            if method.upper() == 'GET':
                response = requests.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = requests.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            # 429: Too Many Requests - 限流，等待后重试
            if response.status_code == 429:
                wait_time = backoff_factor * (2 ** attempt)
                print(f"[Retry] 触发限流，等待 {wait_time}秒后重试 (尝试 {attempt+1}/{max_retries})")
                time.sleep(wait_time)
                continue
            
            # 5xx 服务器错误 - 重试
            if 500 <= response.status_code < 600:
                wait_time = backoff_factor * (2 ** attempt)
                print(f"[Retry] 服务器错误 {response.status_code}，等待 {wait_time}秒后重试")
                time.sleep(wait_time)
                continue
            
            return response
            
        except requests.Timeout:
            wait_time = backoff_factor * (2 ** attempt)
            print(f"[Retry] 请求超时，等待 {wait_time}秒后重试 (尝试 {attempt+1}/{max_retries})")
            time.sleep(wait_time)
            continue
            
        except requests.ConnectionError:
            wait_time = backoff_factor * (2 ** attempt)
            print(f"[Retry] 连接错误，等待 {wait_time}秒后重试 (尝试 {attempt+1}/{max_retries})")
            time.sleep(wait_time)
            continue
            
        except Exception as e:
            # 其他错误直接抛出
            raise
    
    # 所有重试都失败
    raise Exception(f"请求失败，已重试 {max_retries} 次")


# ==================== HTTP请求工具 ====================

def http_get(url: str, params: Dict = None, headers: Dict = None,
             timeout: int = 30, allow_redirects: bool = True) -> str:
    """
    发送GET请求（自动记录到短期记忆）

    Args:
        url: 目标URL
        params: URL参数
        headers: 请求头
        timeout: 超时时间
        allow_redirects: 是否跟随重定向

    Returns:
        响应内容
    """
    memory = get_memory()

    # 检查是否已尝试相同请求（简化检测：只比较URL+params）
    check_params = {"params": params} if params else None
    if memory.has_tried("http_get", url, check_params):
        return f"[Skip] 已尝试过该请求: {url}"

    try:
        response = _http_request_with_retry(
            'GET', url,
            params=params, headers=headers,
            timeout=timeout, allow_redirects=allow_redirects
        )

        output = f"""Status: {response.status_code}
Headers: {dict(response.headers)}
Content-Length: {len(response.text)}

--- Content ---
{response.text}"""

        # 提取flag
        flags = extract_flags(response.text)
        success = response.status_code == 200
        findings = flags if flags else _extract_findings(response.text)

        # 记录到短期记忆
        memory.add_step(
            tool="http_get",
            target=url[:100],
            params={"url": url, "params": params, "headers": headers},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except requests.Timeout:
        error_msg = f"请求超时 ({timeout}秒)"
        memory.add_step(
            tool="http_get",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        error_msg = f"请求错误: {str(e)}"
        memory.add_step(
            tool="http_get",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg


def http_post(url: str, data: Dict = None, json: Dict = None,
              headers: Dict = None, timeout: int = 30) -> str:
    """
    发送POST请求（自动记录到短期记忆）

    Args:
        url: 目标URL
        data: 表单数据
        json: JSON数据
        headers: 请求头
        timeout: 超时时间

    Returns:
        响应内容
    """
    memory = get_memory()

    # 检查是否已尝试相同请求（简化检测：只比较URL+data/json）
    check_params = {"data": data, "json": json} if (data or json) else None
    if memory.has_tried("http_post", url, check_params):
        return f"[Skip] 已尝试过该请求: {url}"

    try:
        response = _http_request_with_retry(
            'POST', url,
            data=data, json=json, headers=headers, timeout=timeout
        )

        output = f"""Status: {response.status_code}
Headers: {dict(response.headers)}
Content-Length: {len(response.text)}

--- Content ---
{response.text}"""

        # 提取flag
        flags = extract_flags(response.text)
        success = response.status_code == 200
        findings = flags if flags else _extract_findings(response.text)

        # 记录到短期记忆
        memory.add_step(
            tool="http_post",
            target=url[:100],
            params={"url": url, "data": data, "json": json},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except requests.Timeout:
        error_msg = f"请求超时 ({timeout}秒)"
        memory.add_step(
            tool="http_post",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        error_msg = f"请求错误: {str(e)}"
        memory.add_step(
            tool="http_post",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg


# ==================== 核心执行工具（带记忆） ====================

def execute_command(cmd: str, timeout: int = 120,
                    skip_if_failed: bool = True, max_failures: int = 2) -> str:
    """
    执行shell命令（自动防重复 + 失败追踪）

    Args:
        cmd: 要执行的命令
        timeout: 超时时间
        skip_if_failed: 是否跳过已多次失败的命令
        max_failures: 最大失败次数

    Returns:
        执行结果
    """
    memory = get_memory()

    # 检查是否已多次失败
    if skip_if_failed and memory.should_skip("command", cmd, None, max_failures):
        fail_count = memory.fail_count("command", cmd)
        return f"[Skip] 该命令已失败 {fail_count} 次，跳过执行"

    try:
        result = run_subprocess(
            cmd,
            shell=True,
            timeout=timeout,
        )

        output = f"""Exit Code: {result.returncode}

--- STDOUT ---
{result.stdout}

--- STDERR ---
{result.stderr}"""

        success = result.returncode == 0

        # 记录到短期记忆
        findings = _extract_findings(output)
        memory.add_step(
            tool="command",
            target=cmd[:100],
            params={"cmd": cmd, "timeout": timeout},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except subprocess.TimeoutExpired:
        error_msg = f"执行超时 ({timeout}秒)"
        memory.add_step(
            tool="command",
            target=cmd[:100],
            params={"cmd": cmd},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        error_msg = f"执行错误: {str(e)}"
        memory.add_step(
            tool="command",
            target=cmd[:100],
            params={"cmd": cmd},
            result=error_msg,
            success=False
        )
        return error_msg


def execute_python_poc(code: str, timeout: int = 120,
                       skip_if_failed: bool = True, max_failures: int = 2,
                       keep: bool = False, memory_meta: Optional[Dict[str, Any]] = None) -> str:
    """
    执行Python PoC代码（自动防重复 + 失败追踪 + 自动清理）

    Args:
        code: Python代码
        timeout: 超时时间
        skip_if_failed: 是否跳过已多次失败的代码
        max_failures: 最大失败次数
        keep: 是否保留文件（用于调试，默认自动删除）

    Returns:
        执行结果
    """
    memory = get_memory()
    code_summary = code[:100] + "..." if len(code) > 100 else code

    action_meta = dict(memory_meta or {})

    # 检查是否已尝试过（成功的不重复执行）
    if memory.has_tried("python_poc", code_summary, None):
        # 写入显式 skip step，避免旧 step 状态泄漏到当前动作
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result="[Skip] 该PoC已执行过",
            success=False,
            action_meta=action_meta,
        )
        return "[Skip] 该PoC已执行过"

    # 检查是否已多次失败
    if skip_if_failed and memory.should_skip("python_poc", code_summary, None, max_failures):
        fail_count = memory.fail_count("python_poc", code_summary)
        # 写入显式 skip step，避免旧 step 状态泄漏到当前动作
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=f"[Skip] 该PoC已失败 {fail_count} 次，跳过执行",
            success=False,
            action_meta=action_meta,
        )
        return f"[Skip] 该PoC已失败 {fail_count} 次，跳过执行"

    import os
    import io
    import sys
    from datetime import datetime

    # 使用 workspace 目录
    workspace = Path(__file__).parent / "workspace"
    workspace.mkdir(exist_ok=True)

    # 生成唯一文件名（时间戳+随机数）
    timestamp = datetime.now().strftime("%H%M%S")
    temp_file = workspace / f"poc_{timestamp}_{os.urandom(2).hex()}.py"

    temp_file_str = str(temp_file)

    # 保存原始stdout以便恢复（避免与调用者的stdout修改冲突）
    _original_stdout = sys.stdout

    try:
        # 写入代码到 workspace/
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(code)

        result = run_subprocess(
            [get_venv_python(), temp_file_str],
            timeout=timeout,
            cwd=workspace,
        )

        # 执行完成后自动清理文件（除非keep=True）
        if not keep:
            try:
                os.unlink(temp_file_str)
            except:
                pass

        output = f"""Exit Code: {result.returncode}

--- STDOUT ---
{result.stdout}

--- STDERR ---
{result.stderr}"""

        success = result.returncode == 0

        # 记录到短期记忆
        findings = _extract_findings(output)
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=output,
            success=success,
            key_findings=findings,
            action_meta=action_meta,
        )

        return output

    except subprocess.TimeoutExpired:
        try:
            os.unlink(temp_file)
        except:
            pass
        error_msg = f"执行超时 ({timeout}秒)"
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=error_msg,
            success=False,
            action_meta=action_meta,
        )
        return error_msg

    except Exception as e:
        try:
            os.unlink(temp_file)
        except:
            pass
        error_msg = f"执行错误: {str(e)}"
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=error_msg,
            success=False,
            action_meta=action_meta,
        )
        return error_msg


# ==================== Web辅助工具 ====================

def extract_form_fields(html: str, form_index: int = 0) -> Dict[str, Any]:
    """提取HTML表单字段"""
    try:
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            return {"error": "未找到表单", "action": "", "method": "GET",
                    "fields": {}, "field_order": [], "form_count": 0, "auth_hints": []}

        form = forms[form_index]
        result = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'fields': {},
            'field_order': [],
            'error': None,
            'form_count': len(forms),
            'auth_hints': []
        }

        # 提取input字段
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            if not name or 'disabled' in input_tag.attrs:
                continue
            field_type = input_tag.get('type', 'text').lower()
            if field_type in ['submit', 'button', 'reset', 'image']:
                continue
            result['fields'][name] = {
                'value': input_tag.get('value', ''),                'type': field_type,
                'hidden': field_type == 'hidden',
                'required': 'required' in input_tag.attrs
            }
            result['field_order'].append(name)

        lower_action = str(result['action'] or '').lower()
        for field_name, field_info in result['fields'].items():
            field_lower = field_name.lower()
            field_type = str(field_info.get('type') or '').lower()
            if any(token in field_lower for token in ['user', 'name', 'email', 'login', 'account']):
                result['auth_hints'].append(f'username_field:{field_name}')
            if any(token in field_lower for token in ['pass', 'pwd']):
                result['auth_hints'].append(f'password_field:{field_name}')
            if any(token in field_lower for token in ['csrf', 'token']):
                result['auth_hints'].append(f'token_field:{field_name}')
            if field_type == 'password' and f'password_field:{field_name}' not in result['auth_hints']:
                result['auth_hints'].append(f'password_field:{field_name}')
            if field_info.get('hidden') and any(token in field_lower for token in ['csrf', 'token', 'session']):
                result['auth_hints'].append(f'hidden_auth_field:{field_name}')

        if any(token in lower_action for token in ['login', 'signin', 'auth', 'check']):
            result['auth_hints'].append(f'login_action:{result["action"]}')

        parsed_action_path = urlparse(result['action']).path if result['action'] else ''
        if parsed_action_path and any(token in parsed_action_path.lower() for token in ['login', 'signin', 'auth', 'check']):
            result['auth_hints'].append(f'login_endpoint:{parsed_action_path}')

        result['auth_hints'] = list(dict.fromkeys(result['auth_hints']))
        return result

    except ImportError:
        return {"error": "BeautifulSoup未安装: pip install beautifulsoup4",
                "action": "", "method": "GET", "fields": {}, "field_order": [], "form_count": 0, "auth_hints": []}
    except Exception as e:
        return {"error": str(e), "action": "", "method": "GET",
                "fields": {}, "field_order": [], "form_count": 0, "auth_hints": []}


def summarize_auth_recon_response(target_url: str, status_code: int, headers: Dict[str, Any], response_text: str) -> Dict[str, Any]:
    """从 recon 响应中提取 auth 场景可复用的结构化发现。"""
    from urllib.parse import urljoin, urlparse

    findings: List[str] = []
    endpoints: List[str] = []
    parameters: List[str] = []
    auth_hints: List[str] = []

    form_info = extract_form_fields(response_text)
    if not form_info.get("error"):
        action = str(form_info.get("action") or "").strip()
        method = str(form_info.get("method") or "GET").upper()
        field_order = list(form_info.get("field_order") or [])
        auth_hints.extend(list(form_info.get("auth_hints") or []))
        if action:
            joined = urljoin(target_url, action)
            parsed = urlparse(joined)
            endpoint = parsed.path or action
            if endpoint:
                endpoints.append(endpoint)
                findings.append(f"Found login form endpoint: {endpoint}")
        if method:
            findings.append(f"Form method: {method}")
        for field_name in field_order:
            parameters.append(field_name)
            findings.append(f"Form field: {field_name}")

    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if set_cookie:
        auth_hints.append("cookie_present")
        findings.append("Set-Cookie observed")
        for token in ["session", "phpsessid", "token", "csrf"]:
            if token in set_cookie.lower():
                auth_hints.append(f"cookie_hint:{token}")

    lower_text = response_text.lower()
    if any(token in lower_text for token in ["login", "signin", "password", "username"]):
        auth_hints.append("login_page_keywords")

    return {
        "status_code": status_code,
        "headers": dict(headers),
        "form_info": form_info,
        "findings": list(dict.fromkeys(findings)),
        "endpoints": list(dict.fromkeys([ep for ep in endpoints if ep])),
        "parameters": list(dict.fromkeys([param for param in parameters if param])),
        "auth_hints": list(dict.fromkeys(auth_hints)),
    }


def summarize_generic_recon_findings(target_url: str, status_code: int, headers: Dict[str, Any], response_text: str) -> Dict[str, Any]:
    """从通用 recon 响应中提取高价值 finding taxonomy。"""
    findings: List[str] = []
    typed_findings: List[Dict[str, Any]] = []
    lower_text = str(response_text or "").lower()
    title_match = re.search(r"<title>(.*?)</title>", response_text or "", re.IGNORECASE | re.DOTALL)
    title_text = title_match.group(1).strip() if title_match else ""

    for item in classify_generic_findings(response_text):
        typed_findings.append(item)
    for item in classify_generic_findings(title_text):
        typed_findings.append(item)

    header_text = "\n".join(f"{key}: {value}" for key, value in dict(headers or {}).items())
    for item in classify_generic_findings(header_text):
        typed_findings.append(item)

    if title_text:
        findings.append(f"Page title: {title_text}")
    if status_code:
        findings.append(f"HTTP status: {status_code}")
    if "phpinfo()" in lower_text or ("php version" in lower_text and "php credits" in lower_text):
        typed_findings.append({"kind": "debug_page", "value": "phpinfo"})
        typed_findings.append({"kind": "info_leak", "value": "phpinfo"})
        findings.append("Debug page detected: phpinfo")

    dedup_typed = list({(item.get('kind'), item.get('value')): item for item in typed_findings}.values())
    return {
        "findings": list(dict.fromkeys(findings)),
        "typed_findings": dedup_typed,
        "title": title_text,
        "status_code": status_code,
        "target_url": target_url,
    }


def summarize_dirsearch_findings(result: Any) -> Dict[str, Any]:
    """把 dirsearch 的 parsed/artifacts 结果归一化为 memory/planner 可消费发现。"""
    parsed = dict(getattr(result, "parsed", {}) or {})
    artifacts = list(getattr(result, "artifacts", []) or [])
    endpoints: List[str] = []
    findings: List[str] = []
    typed_findings: List[Dict[str, Any]] = []

    def add_typed(kind: str, value: str, **metadata: Any) -> None:
        item = {"kind": str(kind or "").strip(), "value": str(value or "").strip(), "metadata": dict(metadata or {})}
        if not item["kind"] or not item["value"]:
            return
        typed_findings.append(item)

    for artifact in artifacts:
        path = str(artifact.get("path") or "").strip()
        if not path:
            continue
        endpoints.append(path)
        status = artifact.get("status")
        if artifact.get("sensitive"):
            findings.append(f"Sensitive path: {path}")
            for derived in classify_generic_findings(path):
                add_typed(derived.get("kind") or "note", path, source="artifact", status=status)
        else:
            findings.append(f"Path: {path}")
            add_typed("endpoint", path, source="artifact", status=status)

    for entry in parsed.get("sensitive_hits") or []:
        path = str(entry.get("path") or "").strip()
        status = entry.get("status")
        if path and f"Sensitive path: {path}" not in findings:
            findings.append(f"Sensitive path: {path}")
        for derived in classify_generic_findings(path):
            add_typed(derived.get("kind") or "note", path, source="parsed_sensitive_hit", status=status)

    for entry in parsed.get("entries") or []:
        path = str(entry.get("path") or "").strip()
        status = entry.get("status")
        if not path:
            continue
        if path not in endpoints:
            endpoints.append(path)
        add_typed("endpoint", path, source="parsed_entry", status=status)
        for derived in classify_generic_findings(path):
            add_typed(derived.get("kind") or "note", path, source="parsed_entry", status=status)

    return {
        "endpoints": list(dict.fromkeys([ep for ep in endpoints if ep])),
        "findings": list(dict.fromkeys(findings)),
        "typed_findings": list({(item.get('kind'), item.get('value')): item for item in typed_findings}.values()),
        "sensitive_hits": list(parsed.get("sensitive_hits") or []),
        "count": int(parsed.get("count") or 0),
    }


# ==================== 工具封装（带记忆） ====================

def sqlmap_scan_url(url: str, memory_meta: Optional[Dict[str, Any]] = None, **kwargs) -> str:
    """SQLMap扫描（防重复）"""
    memory = get_memory()
    memory_meta = dict(memory_meta or {})

    # 检查是否已尝试
    if memory.has_tried("sqlmap", url, kwargs):
        return f"[Skip] SQLMap已扫描过 {url}"

    if not TOOLKIT_AVAILABLE or sqlmap_scan is None:
        return "[Error] SQLMap工具未安装"

    result = sqlmap_scan(url, **kwargs)

    # 记录
    success = result.success
    findings = ["发现注入点"] if "injection" in result.stdout.lower() else []
    memory.add_step(
        tool="sqlmap",
        target=url,
        params=kwargs,
        result=result.stdout[:500] if success else result.stderr,
        success=success,
        key_findings=findings,
        action_meta=memory_meta,
    )

    return f"[SQLMap] {url}\n{result.stdout if success else result.stderr}"


def sqlmap_deep_scan_url(url: str, memory_meta: Optional[Dict[str, Any]] = None, **kwargs) -> str:
    """SQLMap深度扫描"""
    return sqlmap_scan_url(url, memory_meta=memory_meta, level=5, risk=3, **kwargs)


def dirsearch_scan_url(url: str, memory_meta: Optional[Dict[str, Any]] = None, **kwargs) -> str:
    """Dirsearch扫描（防重复）"""
    memory = get_memory()
    memory_meta = dict(memory_meta or {})

    if memory.has_tried("dirsearch", url, kwargs):
        return f"[Skip] Dirsearch已扫描过 {url}"

    if not TOOLKIT_AVAILABLE or dirsearch_scan is None:
        return "[Error] Dirsearch工具未安装"

    result = dirsearch_scan(url=url, **kwargs)
    summary = summarize_dirsearch_findings(result)
    findings = list(summary.get("findings") or [])
    typed_findings = list(summary.get("typed_findings") or [])
    observation_payload = []
    for item in typed_findings:
        kind = str(item.get("kind") or "").strip()
        value = str(item.get("value") or "").strip()
        if kind and value:
            observation_payload.append({
                "kind": kind,
                "value": value,
                "metadata": dict(item.get("metadata") or {}),
            })
    for endpoint in summary.get("endpoints") or []:
        if endpoint not in findings:
            findings.append(endpoint)
        observation_payload.append({"kind": "endpoint", "value": endpoint, "metadata": {"source": "dirsearch"}})
    for item in typed_findings:
        kind = str(item.get("kind") or "").strip()
        value = str(item.get("value") or "").strip()
        if kind and value:
            marker = f"{kind}:{value}"
            if marker not in findings:
                findings.append(marker)

    output_text = result.stdout if result.stdout else result.stderr
    novelty = {
        "endpoints": list(summary.get("endpoints") or []),
        "count": int(summary.get("count") or 0),
        "sensitive_hits": list(summary.get("sensitive_hits") or []),
        "yield_class": "empty" if not summary.get("endpoints") else ("high" if summary.get("sensitive_hits") else "low"),
    }
    memory.add_step(
        tool="dirsearch",
        target=url,
        params=kwargs,
        result=output_text[:500] if len(output_text) > 500 else output_text,
        success=result.success,
        key_findings=findings,
        action_meta=memory_meta,
        parsed={"dirsearch_summary": summary, "novelty": novelty},
        artifacts=list(getattr(result, "artifacts", []) or []),
        observations=observation_payload,
    )

    if result.success:
        header = f"[Dirsearch] {url}"
    else:
        header = f"[Dirsearch][Error] {url} (exit={result.exit_code})"

    detail_lines = [header]
    detail_lines.extend(findings[:10])
    if output_text:
        detail_lines.append(output_text)
    return "\n".join(detail_lines)


def quick_dir_scan(url: str, extensions: List[str] = None, memory_meta: Optional[Dict[str, Any]] = None) -> str:
    """快速目录扫描"""
    if extensions is None:
        extensions = ["php", "html", "js", "css", "txt"]
    return dirsearch_scan_url(url=url, extensions=extensions, threads=30, memory_meta=memory_meta)


# ==================== 记忆查询 ====================

def get_memory_summary() -> str:
    """获取当前解题摘要（包含步数统计）"""
    memory = get_memory()
    summary = memory.get_summary()

    # 添加步数统计
    step_count = len(memory.steps) if hasattr(memory, 'steps') else 0
    if step_count > 0:
        summary = f"[进度] 已有 {step_count} 步操作\n\n" + summary

    # 步数过多警告
    if step_count >= 20:
        summary = f"[!] 警告：已进行 {step_count} 步，可能陷入僵局，建议更换策略\n\n" + summary

    return summary


def get_step_count() -> int:
    """获取当前解题步数"""
    memory = get_memory()
    return len(memory.steps) if hasattr(memory, 'steps') else 0


def get_status() -> str:
    """快速获取当前解题状态（一行）"""
    memory = get_memory()
    step_count = len(memory.steps) if hasattr(memory, 'steps') else 0
    prob_type = memory.target.problem_type or "未知"
    url = memory.target.url or "无"
    flags = memory.target.flags or []

    status = f"[状态] 类型:{prob_type} | 步数:{step_count} | URL:{url[:40]}"
    if flags:
        status += f" | Flag:{flags[0]}"
    return status


def analyze_result(result: str) -> Dict[str, str]:
    """
    智能分析工具执行结果，判断成功/失败/需进一步分析
    
    Args:
        result: 工具执行输出
    
    Returns:
        dict: {"status": "success/failure/uncertain", "reason": "原因", "details": ["详情"]}
    """
    result_lower = result.lower()
    details = []
    
    # 检查明显成功标志
    success_keywords = ['successful', 'success!', 'found', 'flag{', 'correct', 'right!']
    for kw in success_keywords:
        if kw in result_lower:
            details.append(f"发现成功关键字: {kw}")
    
    # 检查明显失败标志
    failure_keywords = [
        ('error', '错误'),
        ('failed', '失败'),
        ('not found', '未找到'),
        ('denied', '拒绝访问'),
        ('incorrect', '不正确'),
        ('timeout', '超时'),
        ('forbidden', '禁止访问'),
        ('unauthorized', '未授权'),
    ]
    for kw, desc in failure_keywords:
        if kw in result_lower:
            details.append(f"发现失败关键字: {desc}")
    
    # 检查HTTP状态码
    import re
    status_match = re.search(r'Status:\s*(\d+)', result)
    if status_match:
        status_code = int(status_match.group(1))
        if 200 <= status_code < 300:
            details.append(f"HTTP状态码成功: {status_code}")
        elif 400 <= status_code < 500:
            details.append(f"HTTP客户端错误: {status_code}")
        elif 500 <= status_code < 600:
            details.append(f"HTTP服务器错误: {status_code}")
    
    # 综合判断
    if any(kw in result_lower for kw in ['flag{', 'successful', 'success!']):
        status = 'success'
        reason = '发现成功标志'
    elif any(kw in result_lower for kw in ['error:', 'failed', 'not found', 'timeout', 'denied']):
        status = 'failure'
        reason = '发现失败标志'
    elif status_match and int(status_match.group(1)) >= 400:
        status = 'failure'
        reason = f'HTTP错误 {status_match.group(1)}'
    else:
        status = 'uncertain'
        reason = '结果不明确，需人工判断'
    
    return {'status': status, 'reason': reason, 'details': details}


def get_suggested_next() -> List[str]:
    """获取建议的下一步"""
    return get_memory().get_suggested_next()


def has_tried(tool: str, target: str, params: Dict = None) -> bool:
    """检查是否已尝试过"""
    return get_memory().has_tried(tool, target, params)


def check_flag() -> Optional[str]:
    """Check if flag found, save experience and generate report"""
    memory = get_memory()
    flags = memory.target.flags
    if flags:
        flag = flags[0]
        print(f"[Agent] Flag found: {flag}")

        # Save experience
        prob_type = "unknown"
        target = ""
        steps = []
        
        if LONG_MEMORY_AVAILABLE and auto_save_experience:
            try:
                prob_type = memory.target.problem_type or "unknown"
                target = memory.target.url or ""
                steps = [
                    {"tool": step.tool, "target": step.target, "success": step.success}
                    for step in memory.steps
                ]
                techniques = list(set([step.tool for step in memory.steps if step.success]))

                exp_file = auto_save_experience(
                    problem_type=prob_type,
                    target=target,
                    steps=steps,
                    flag=flag,
                    key_techniques=techniques
                )
                print(f"[Memory] Experience saved: {exp_file}")
            except Exception as e:
                print(f"[Memory] Save failed: {e}")

        # Generate solution report
        try:
            from long_memory import auto_memory
            report = auto_memory.generate_report(problem_type=prob_type, target=target, steps=steps, flag=flag)
            print('')
            print(report)
        except Exception as re:
            print(f"[Report] Error: {re}")

        print("[Memory] Done, clearing short memory")
        reset_memory()
        clean_workspace()
        return flag
    return None

# ==================== 长期记忆 ====================

def load_long_memory(category: str, name: str) -> Optional[str]:
    """
    加载长期记忆

    Args:
        category: 类别 (experiences, pocs, patterns)
        name: 记忆名称

    Returns:
        记忆内容
    """
    path = Path(__file__).parent / "long_memory" / category / f"{name}.md"
    if path.exists():
        return path.read_text(encoding="utf-8")

    # 尝试skills目录
    path = Path(__file__).parent / "skills" / name / "SKILL.md"
    if path.exists():
        return path.read_text(encoding="utf-8")

    return None


def save_long_memory(category: str, name: str, content: str):
    """保存到长期记忆"""
    dir_path = Path(__file__).parent / "long_memory" / category
    dir_path.mkdir(parents=True, exist_ok=True)

    path = dir_path / f"{name}.md"
    path.write_text(content, encoding="utf-8")
    print(f"[Memory] 已保存到长期记忆: {category}/{name}")


def list_long_memory(category: str = "") -> List[str]:
    """列出长期记忆"""
    base_path = Path(__file__).parent / "long_memory"

    if category:
        path = base_path / category
        if path.exists():
            return [f.stem for f in path.glob("*.md")]
        return []

    # 列出所有
    result = []
    for cat in ["experiences", "pocs", "patterns"]:
        cat_path = base_path / cat
        if cat_path.exists():
            for f in cat_path.glob("*.md"):
                result.append(f"{cat}/{f.stem}")
    return result


# ==================== 辅助函数 ====================

def _extract_findings(output: str) -> List[str]:
    """从输出中提取关键发现"""
    findings = []

    patterns = {
        "开放端口": r'(\d+/tcp\s+open)',
        "发现目录": r'(200|301|302)\s+(/[^\s]+)',
        "SQL注入": r'(injection|injection|union|select)',
        "Flag": r'(flag\{[^}]+\}|ctf\{[^}]+\})',
    }

    for desc, pattern in patterns.items():
        if re.search(pattern, output, re.IGNORECASE):
            findings.append(desc)

    auth_summary_match = re.search(r'AUTH_RECON_SUMMARY:\s*(\{.*\})', output, re.DOTALL)
    if auth_summary_match:
        try:
            auth_summary = json.loads(auth_summary_match.group(1))
        except json.JSONDecodeError:
            auth_summary = {}
        for endpoint in auth_summary.get("endpoints", []) or []:
            findings.append(f"Found login form endpoint: {endpoint}")
        for param in auth_summary.get("parameters", []) or []:
            findings.append(f"Form field: {param}")
        for hint in auth_summary.get("auth_hints", []) or []:
            findings.append(f"Auth hint: {hint}")

    return list(dict.fromkeys(findings))


def extract_flags(text: str) -> List[str]:
    """从文本中提取flag"""
    return extract_flag_candidates(text)


def summarize_output(output: str, max_length: int = 2000) -> str:
    """截断过长输出"""
    if len(output) <= max_length:
        return output
    head_len = max_length // 2
    tail_len = max_length - head_len - 100
    return f"""{output[:head_len]}

... [输出过长，共 {len(output)} 字符] ...

{output[-tail_len:]}"""


# ==================== Fenjing SSTI工具 ====================

_fenjing_available = False
_fenjing_path = Path(__file__).parent / "tools_source" / "Fenjing"

def _init_fenjing():
    """初始化fenjing模块路径"""
    global _fenjing_available
    if str(_fenjing_path) not in sys.path:
        sys.path.insert(0, str(_fenjing_path))
    try:
        from fenjing import exec_cmd_payload, config_payload
        from fenjing.const import EVAL, STRING
        _fenjing_available = True
        return True
    except ImportError:
        return False

def fenjing_generate_payload(command: str = "id", blacklist: list = None) -> dict:
    """
    生成绕过WAF的SSTI payload

    Args:
        command: 要执行的命令，默认为"id"
        blacklist: 自定义黑名单，为None时使用默认

    Returns:
        dict: {"success": bool, "payload": str, "will_print": bool, "error": str}
    """
    if not _init_fenjing():
        return {"success": False, "error": "fenjing module not available", "payload": "", "will_print": False}

    memory = get_memory()
    cache_key = f"{command}_{str(blacklist)}"

    # 检查是否已生成过
    if memory.has_tried("fenjing_gen", cache_key, None):
        return {"success": True, "payload": "[Cached]", "will_print": True, "error": ""}

    try:
        from fenjing import exec_cmd_payload

        # 默认黑名单
        if blacklist is None:
            blacklist = [
                "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
                "[", '"', "'", "_", ".", "+", "~", "{{",
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                "0","1","2","3","4","5","6","7","8","9"
            ]

        def waf(s: str) -> bool:
            return all(word not in s for word in blacklist)

        payload, will_print = exec_cmd_payload(waf, command)

        memory.add_step(
            tool="fenjing_gen",
            target=f"cmd:{command}",
            params={"command": command},
            result=f"payload generated, will_print={will_print}",
            success=True
        )

        return {
            "success": True,
            "payload": payload,
            "will_print": will_print,
            "error": ""
        }

    except Exception as e:
        memory.add_step(
            tool="fenjing_gen",
            target=f"cmd:{command}",
            params={},
            result=f"error: {str(e)}",
            success=False
        )
        return {"success": False, "error": str(e), "payload": "", "will_print": False}


def fenjing_crack_form(
    url: str,
    method: str = "GET",
    inputs: str = "name",
    command: str = "id",
    detect_mode: str = "fast",
    timeout: int = 300,
    extra_params: dict = None,
    extra_data: dict = None,
    headers: dict = None
) -> dict:
    """
    使用fenjing攻击指定表单，自动绕过WAF

    Args:
        url: 目标URL
        method: HTTP方法 GET/POST
        inputs: 要攻击的输入字段名，多个用逗号分隔
        command: 要执行的命令
        detect_mode: 检测模式 fast/accurate
        timeout: 超时时间
        extra_params: 额外GET参数
        extra_data: 额外POST参数
        headers: 自定义请求头

    Returns:
        dict: {"success": bool, "output": str, "flag": str or None, "error": str}
    """
    memory = get_memory()
    cache_key = f"{url}:{method}:{inputs}:{command}"

    # 防重复检查
    if memory.has_tried("fenjing_crack", cache_key, None):
        return {"success": True, "output": "[Cached] Already cracked", "flag": None, "error": ""}

    # 检查失败次数
    if memory.should_skip("fenjing_crack", cache_key, None, max_failures=2):
        return {"success": False, "output": "", "flag": None, "error": "Too many failures, skipping"}

    if not _init_fenjing():
        return {"success": False, "output": "", "flag": None, "error": "fenjing not available"}

    try:
        import requests

        # 先尝试自动生成payload并发送
        payload_result = fenjing_generate_payload(command)
        if not payload_result["success"]:
            return {"success": False, "output": "", "flag": None, "error": payload_result["error"]}

        payload = payload_result["payload"]
        will_print = payload_result["will_print"]

        # 发送payload
        input_fields = inputs.split(",")
        responses = []

        for field in input_fields:
            field = field.strip()
            if method.upper() == "GET":
                params = {field: payload}
                if extra_params:
                    params.update(extra_params)
                resp = requests.get(url, params=params, headers=headers or {}, timeout=30)
            else:
                data = {field: payload}
                if extra_data:
                    data.update(extra_data)
                resp = requests.post(url, data=data, headers=headers or {}, timeout=30)

            responses.append(f"[{field}] Status: {resp.status_code}\n{resp.text[:500]}")

        output = "\n---\n".join(responses)

        # 提取flag
        flags = extract_flags(output)
        if flags:
            memory.add_flag(flags[0])

        success = "error" not in output.lower() and resp.status_code == 200

        memory.add_step(
            tool="fenjing_crack",
            target=url,
            params={"method": method, "inputs": inputs, "command": command},
            result=output[:500],
            success=success,
            key_findings=["SSTI exploit"] if success else []
        )

        return {
            "success": success,
            "output": output,
            "flag": flags[0] if flags else None,
            "error": ""
        }

    except Exception as e:
        memory.add_step(
            tool="fenjing_crack",
            target=url,
            params={},
            result=f"error: {str(e)}",
            success=False
        )
        return {"success": False, "output": "", "flag": None, "error": str(e)}


def fenjing_scan(url: str, detect_mode: str = "fast", timeout: int = 300) -> dict:
    """
    扫描目标网站自动发现SSTI漏洞

    Args:
        url: 目标URL
        detect_mode: 检测模式 fast/accurate
        timeout: 扫描超时

    Returns:
        dict: {"success": bool, "forms": list, "output": str, "error": str}
    """
    memory = get_memory()

    if memory.has_tried("fenjing_scan", url, None):
        return {"success": True, "forms": [], "output": "[Cached] Already scanned", "error": ""}

    if not _init_fenjing():
        return {"success": False, "forms": [], "output": "", "error": "fenjing not available"}

    try:
        import requests
        from bs4 import BeautifulSoup

        # 获取页面并分析表单
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        form_info = []
        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]

            if inputs:
                form_info.append({
                    "index": i,
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })

        # 记录发现
        memory.update_target(endpoints=[f"form_{f['index']}" for f in form_info])

        memory.add_step(
            tool="fenjing_scan",
            target=url,
            params={},
            result=f"Found {len(form_info)} forms",
            success=True,
            key_findings=[f"发现{len(form_info)}个表单"] if form_info else []
        )

        return {
            "success": True,
            "forms": form_info,
            "output": f"发现 {len(form_info)} 个表单，建议逐一测试",
            "error": ""
        }

    except Exception as e:
        memory.add_step(
            tool="fenjing_scan",
            target=url,
            params={},
            result=f"error: {str(e)}",
            success=False
        )
        return {"success": False, "forms": [], "output": "", "error": str(e)}


__all__ = [
    # 记忆管理
    "reset_memory",
 "get_memory",
    "init_problem",
    "get_memory_summary",
    "get_suggested_next",
    "has_tried",
    "check_flag",
    "load_long_memory",
    "save_long_memory",
    "list_long_memory",
    "clean_workspace",  # 新增清理函数

    # 核心工具
    "execute_command",
    "execute_python_poc",

    # Web辅助
    "extract_form_fields",
    "extract_flags",

    # 封装工具
    "sqlmap_scan_url",
    "sqlmap_deep_scan_url",
    "dirsearch_scan_url",
    "quick_dir_scan",

    # SSTI工具
    "fenjing_generate_payload",
    "fenjing_crack_form",
    "fenjing_scan",

    # RAG 检索
    "retrieve_rag_knowledge",
    "update_problem_type",
    "get_available_resources",

    # 辅助
    "summarize_output",
]



# ==================== 检查点功能 ====================

import hashlib

_CHECKPOINT_DIR = Path(__file__).parent / "checkpoints"

def save_checkpoint(name: str = "default") -> str:
    """
    保存当前解题进度到检查点文件
    
    Args:
        name: 检查点名称，默认"default"
    
    Returns:
        检查点文件路径
    """
    global _short_memory_instance
    if _short_memory_instance is None:
        return "[Error] 无解题进度可保存"
    
    _CHECKPOINT_DIR.mkdir(exist_ok=True)
    
    # 生成唯一文件名
    md5 = hashlib.md5(name.encode("utf-8")).hexdigest()[:8]
    ckpt_file = _CHECKPOINT_DIR / f"ckpt_{md5}.json"
    
    # 保存记忆数据
    data = {
        "name": name,
        "memory": _short_memory_instance.to_dict() if hasattr(_short_memory_instance, 'to_dict') else {},
        "timestamp": str(__import__("datetime").datetime.now()),
    }
    
    import json
    with open(ckpt_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    return f"[Checkpoint] 已保存: {ckpt_file}"

def load_checkpoint(name: str = "default") -> str:
    """
    从检查点文件恢复解题进度
    
    Args:
        name: 检查点名称，默认"default"
    
    Returns:
        恢复结果信息
    """
    global _short_memory_instance
    
    md5 = hashlib.md5(name.encode("utf-8")).hexdigest()[:8]
    ckpt_file = _CHECKPOINT_DIR / f"ckpt_{md5}.json"
    
    if not ckpt_file.exists():
        return f"[Error] 检查点不存在: {name}"
    
    import json
    try:
        with open(ckpt_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 恢复记忆
        if _short_memory_instance and "memory" in data:
            mem_data = data["memory"]
            # 恢复到短期记忆
            if "steps" in mem_data:
                for step in mem_data["steps"]:
                    _short_memory_instance.add_step(
                        tool=step.get("tool", "unknown"),
                        target=step.get("target", ""),
                        params=step.get("params"),
                        result=step.get("result", ""),
                        success=step.get("success", False),
                        key_findings=step.get("key_findings")
                    )
        
        return f"[Checkpoint] 已恢复: {name} (时间: {data.get('timestamp', 'unknown')})"
    except Exception as e:
        return f"[Error] 恢复失败: {str(e)}"

def list_checkpoints() -> List[str]:
    """
    列出所有检查点
    
    Returns:
        检查点名称列表
    """
    _CHECKPOINT_DIR.mkdir(exist_ok=True)
    import os
    files = [f.name for f in _CHECKPOINT_DIR.glob("ckpt_*.json")]
    return files


def clean_workspace():
    """
    清理工作区中的临时脚本文件
    在解题成功后调用，保持环境整洁
    """
    import shutil
    workspace = Path(__file__).parent / "workspace"
    if not workspace.exists():
        return

    deleted = 0
    for f in workspace.glob("poc_*.py"):
        try:
            f.unlink()
            deleted += 1
        except:
            pass

    # 清理 pycache
    pycache = workspace / "__pycache__"
    if pycache.exists():
        try:
            shutil.rmtree(pycache)
        except:
            pass

    if deleted > 0:
        print(f"[Workspace] 清理 {deleted} 个临时脚本")

# ============================================================
# AWD (Attack With Defense) 板块
# ============================================================

def init_awd(target_url: str = None, target_code: str = None, description: str = "", hint: str = "") -> dict:
    """
    初始化 AWD 题目
    
    Args:
        target_url: 攻击目标的 URL
        target_code: 待分析的代码（防御阶段用）
        description: 题目描述
        hint: 提示
    
    Returns:
        初始化信息
    """
    reset_memory()
    memory = get_memory()
    
    # 标记为 AWD 模式
    memory.update_target(problem_type="awdp")
    memory.target.awd_mode = True
    memory.target.awd_phase = "attack"
    
    # 攻击目标 URL
    if target_url:
        memory.update_target(url=target_url)
    
    # 代码（防御阶段分析用）
    if target_code:
        memory.target.target_code = target_code
    
    return {
        "phase": "attack",
        "target_url": target_url,
        "message": "AWD 题目已初始化，当前为攻击阶段，可用 switch_awd_phase('defense') 切换到防御阶段"
    }


def switch_awd_phase(new_phase: str) -> dict:
    """
    切换 AWD 阶段
    
    Args:
        new_phase: "attack" 或 "defense"
    """
    memory = get_memory()
    
    if not memory.target.awd_mode:
        return {"error": "当前不是 AWD 模式，请先调用 init_awd()"}
    
    if new_phase not in ["attack", "defense"]:
        return {"error": f"无效阶段: {new_phase}，请使用 'attack' 或 'defense'"}
    
    old_phase = memory.target.awd_phase
    memory.target.awd_phase = new_phase
    
    return {
        "old_phase": old_phase,
        "new_phase": new_phase,
        "message": f"已从 {old_phase} 切换到 {new_phase}"
    }


def get_awd_status() -> dict:
    """
    获取 AWD 状态
    """
    memory = get_memory()
    
    if not getattr(memory.target, 'awd_mode', False):
        return {"mode": "normal", "phase": None}
    
    return {
        "mode": "awd",
        "phase": memory.target.awd_phase,
        "target_url": memory.target.url,
        "flags": memory.target.flags,
        "patch_count": len(memory.target.patches),
    }


def detect_vulnerabilities(code: str) -> List[Dict]:
    """
    检测代码中的常见漏洞
    
    Args:
        code: 待分析的代码
    
    Returns:
        漏洞列表
    """
    vulns = []
    
    # SQL 注入检测
    sqli_patterns = [
        (r'execute\s*\(\s*["\'].*?%s', "SQL注入 - 字符串拼接"),
        (r'query\s*\(\s*["\'].*?\+', "SQL注入 - 变量拼接"),
        (r'mysql_query\s*\(.*?\+', "SQL注入 - MySQL直接拼接"),
    ]
    for pattern, desc in sqli_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "sqli",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    # XSS 检测
    xss_patterns = [
        (r'echo\s*\$_(?:GET|POST|REQUEST)', "XSS - 直接输出用户输入"),
        (r'\$.*\.innerHTML\s*=', "XSS - innerHTML 赋值"),
        (r'print\s*\$_(?:GET|POST|REQUEST)', "XSS - print 输出用户输入"),
    ]
    for pattern, desc in xss_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "xss",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    # 命令执行检测
    rce_patterns = [
        (r'(?:exec|system|shell_exec|popen)\s*\(\s*\$', "RCE - 危险函数"),
        (r'eval\s*\(\s*\$', "RCE - eval 使用用户输入"),
        (r'assert\s*\(\s*\$', "RCE - assert 使用用户输入"),
        (r'call_user_func\s*\(\s*\$', "RCE - 动态函数调用"),
    ]
    for pattern, desc in rce_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "rce",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    # 文件操作漏洞
    file_patterns = [
        (r'include\s*\(\s*\$', "LFI - 文件包含"),
        (r'require\s*\(\s*\$', "LFI - 文件包含"),
        (r'file_get_contents\s*\(\s*\$', "LFI - 文件读取"),
    ]
    for pattern, desc in file_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "lfi",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    return vulns


def generate_fix_suggestion(vuln_type: str) -> str:
    """生成修复建议"""
    suggestions = {
        "sqli": "使用预处理语句(Prepared Statements)或 ORM 框架",
        "xss": "使用 htmlspecialchars() 转义输出，或设置 CSP 头",
        "rce": "避免使用危险函数，使用白名单限制输入",
        "lfi": "使用 basename() 过滤路径，禁止 ../ 跳转",
        "ssrf": "限制可访问的 URL 白名单",
    }
    return suggestions.get(vuln_type, "参考安全编码规范")


def search_awd_patch(vuln_type: str, language: str = None) -> Optional[Dict]:
    """
    检索 AWD 修补建议（优先 awd_patches）
    """
    from pathlib import Path
    
    # 1. 优先从 awd_patches 检索
    awd_base = Path(__file__).parent / "long_memory" / "awd_patches"
    
    if awd_base.exists():
        type_dir = awd_base / vuln_type
        if type_dir.exists():
            for exp_file in sorted(type_dir.glob("*.md")):
                content = exp_file.read_text(encoding="utf-8")
                return {
                    "source": "awd_patches",
                    "file": exp_file.name,
                    "content": content[:1000]
                }
    
    return None


def analyze_code(code: str) -> dict:
    """
    分析代码找出漏洞点和修补建议
    """
    memory = get_memory()
    memory.target.target_code = code
    
    # 1. 检测漏洞
    vulns = detect_vulnerabilities(code)
    
    # 2. 为每个漏洞检索修复建议
    for vuln in vulns:
        patch_info = search_awd_patch(vuln["type"])
        if patch_info:
            vuln["fix_source"] = patch_info.get("source", "unknown")
            vuln["fix_reference"] = patch_info.get("content", "")[:200]
        
        vuln["fix_suggestion"] = generate_fix_suggestion(vuln["type"])
        
        memory.add_patch(
            location=vuln.get("location", "unknown"),
            vuln_type=vuln.get("type", "unknown"),
            fix_suggestion=vuln["fix_suggestion"],
            code_snippet=vuln.get("match", "")
        )
    
    return {
        "vulnerabilities": vulns,
        "total_found": len(vulns),
        "patches": memory.target.patches
    }


def get_patch_summary() -> str:
    """获取修补点摘要"""
    memory = get_memory()
    return memory.get_patch_summary()


# ============================================================
# 交互模式 - 用户实时介入机制
# ============================================================

import threading
import time
from datetime import datetime
from pathlib import Path

# 全局交互管理器实例
_interaction_manager: Optional["InteractionManager"] = None
_interaction_lock = threading.Lock()


class InteractionManager:
    """
    管理用户与 Agent 的实时交互。

    通过文件系统进行通信：
    - status.json: Agent 写入当前状态，用户可随时读取
    - guidance.json: 用户写入 guidance，Agent 下步读取
    - step.lock: Agent 执行中时存在，防止用户误读
    """

    def __init__(self, enabled: bool = False, state_dir: str = None):
        self.enabled = enabled
        if state_dir is None:
            state_dir = Path.home() / ".ctf_agent"
        else:
            state_dir = Path(state_dir)
        self.state_dir = state_dir
        self.status_file = state_dir / "status.json"
        self.guidance_file = state_dir / "guidance.json"
        self.lock_file = state_dir / "step.lock"
        self._ensure_dir()

    def _ensure_dir(self):
        """确保状态目录存在"""
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, file: Path, data: dict):
        """原子写入 JSON 文件"""
        tmp = file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.rename(file)

    def _read_json(self, file: Path) -> Optional[dict]:
        """读取 JSON 文件"""
        if not file.exists():
            return None
        try:
            return json.loads(file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, IOError):
            return None

    def _write_status(self, step_num: int, action: dict, result: Any,
                      findings: List[str], problem_type: str,
                      total_failures: int, message: str = ""):
        """
        写入当前状态到 status.json

        用户可在任意时刻读取此文件查看进度。
        """
        if not self.enabled:
            return

        status = {
            "step": step_num,
            "action": action.get("type", "unknown") if action else "unknown",
            "target": action.get("target", "") if action else "",
            "description": action.get("description", "") if action else "",
            "result": message or str(result)[:500] if result else "",
            "findings": findings,
            "problem_type": problem_type,
            "total_failures": total_failures,
            "timestamp": datetime.now().isoformat(),
            "agent_state": "running",
        }
        self._write_json(self.status_file, status)

    def _write_completed(self, flag: str = None, message: str = ""):
        """写入完成状态"""
        if not self.enabled:
            return

        status = {
            "step": -1,
            "agent_state": "completed",
            "flag": flag,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        self._write_json(self.status_file, status)

    def _write_aborted(self, message: str = ""):
        """写入终止状态"""
        if not self.enabled:
            return

        status = {
            "step": -1,
            "agent_state": "aborted",
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        self._write_json(self.status_file, status)

    def _acquire_lock(self):
        """获取锁，表示 Agent 正在决策/执行"""
        if not self.enabled:
            return
        self.lock_file.write_text(str(os.getpid()), encoding="utf-8")

    def _release_lock(self):
        """释放锁"""
        if not self.enabled:
            return
        if self.lock_file.exists():
            self.lock_file.unlink()

    def check_guidance(self) -> Optional[dict]:
        """
        检查并读取用户注入的 guidance。

        读取后立即删除文件，确保 guidance 只被使用一次。

        Returns:
            guidance dict 或 None
            {
                "type": "inject" | "abort" | "inspect",
                "content": str,  # inject 的内容或 inspect 的命令
                "timestamp": str
            }
        """
        if not self.enabled:
            return None
        if not self.guidance_file.exists():
            return None

        guidance = self._read_json(self.guidance_file)
        if guidance:
            try:
                self.guidance_file.unlink()
            except OSError:
                pass
        return guidance

    def get_current_status(self) -> Optional[dict]:
        """获取当前状态（供 inspect 命令使用）"""
        return self._read_json(self.status_file)

    def clear_guidance(self):
        """清除 pending guidance（用户在 agent 运行中途可用来取消）"""
        if self.guidance_file.exists():
            try:
                self.guidance_file.unlink()
            except OSError:
                pass


def get_interaction_manager() -> InteractionManager:
    """获取全局交互管理器实例"""
    global _interaction_manager
    if _interaction_manager is None:
        with _interaction_lock:
            if _interaction_manager is None:
                _interaction_manager = InteractionManager(enabled=False)
    return _interaction_manager


def init_interaction(enabled: bool = False, state_dir: str = None) -> InteractionManager:
    """初始化交互管理器"""
    global _interaction_manager
    with _interaction_lock:
        _interaction_manager = InteractionManager(enabled=enabled, state_dir=state_dir)
    return _interaction_manager


def check_user_guidance() -> Optional[dict]:
    """快捷方法：检查用户 guidance"""
    return get_interaction_manager().check_guidance()


def write_agent_status(step_num: int, action: dict, result: Any,
                       findings: List[str], problem_type: str,
                       total_failures: int, message: str = ""):
    """快捷方法：写入 agent 状态"""
    get_interaction_manager()._write_status(
        step_num, action, result, findings, problem_type, total_failures, message
    )


def write_agent_completed(flag: str = None, message: str = ""):
    """快捷方法：写入完成状态"""
    get_interaction_manager()._write_completed(flag, message)


def write_agent_aborted(message: str = ""):
    """快捷方法：写入终止状态"""
    get_interaction_manager()._write_aborted(message)
