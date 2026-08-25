"""runner 核心单测：不 spawn 真进程，直接喂合成 stream-json 流给 StreamParser。

流形态对齐实测（CLI v2.1.238）：混有非 JSON 行；init 带 session_id；
result 带 num_turns/stop_reason/total_cost_usd。
"""

import json

from src import runner as runner_mod
from src.providers import SolverConfig
from src.runner import (AgentResult, AgentTask, StreamParser, _RESUME_PROMPT,
                        _sanitize_env, extract_final_answer, extract_handoff)


def _mk(**kw):
    base = dict(provider="glm", base_url="https://open.bigmodel.cn/api/anthropic",
                api_key="sk-test", model="glm-5.3", small_fast_model="glm-5.3",
                max_turns=10, session_seconds=60, reasoning=False)
    base.update(kw)
    return SolverConfig(**base)


def _assistant(content_blocks, usage=None):
    msg = {"role": "assistant", "content": content_blocks}
    if usage:
        msg["usage"] = usage
    return json.dumps({"type": "assistant", "message": msg, "session_id": "s1"})


def _tool_use(uid, name, input_):
    return {"type": "tool_use", "id": uid, "name": name, "input": input_}


def _text(t):
    return {"type": "text", "text": t}


def _tool_result(uid, text):
    return json.dumps({
        "type": "user",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": uid,
             "content": [{"type": "text", "text": text}]}
        ]},
        "session_id": "s1",
    })


def _result(**kw):
    base = {"type": "result", "subtype": "success", "is_error": False,
            "result": "Done!", "num_turns": 3, "stop_reason": "end_turn",
            "session_id": "sess-123", "total_cost_usd": 0.0123,
            # 实测：真实用量在 result.usage（assistant 事件的 usage 常为 0）
            "usage": {"input_tokens": 500, "cache_read_input_tokens": 400,
                      "output_tokens": 100, "cache_creation_input_tokens": 0}}
    base.update(kw)
    return json.dumps(base)


def test_parse_full_stream_with_junk_lines():
    facts = []
    task = AgentTask(on_fact=facts.append)
    p = StreamParser(task)

    # 实测存在的两类非 JSON 行：stdin 警告 + [claude-code:…] 遥测前缀
    p.feed_line("Warning: no stdin data received in 3s, proceeding without it.\n")
    p.feed_line('[claude-code:unrecognized_model] {"model":"glm-5"}\n')
    # init
    p.feed_line(json.dumps({"type": "system", "subtype": "init",
                            "session_id": "sess-123", "model": "glm-5.3"}) + "\n")
    # tool_use → tool_result 配对
    p.feed_line(_assistant([_tool_use("t1", "Read", {"file_path": "hello.txt"})],
                           usage={"input_tokens": 100, "output_tokens": 5}) + "\n")
    p.feed_line(_tool_result("t1", "marker=at1-abc\n") + "\n")
    # 先吐 Handoff，再说 Done!（dcr 教训场景）
    p.feed_line(_assistant([_text("<Handoff>已完成：含 at1-abc</Handoff>")]) + "\n")
    p.feed_line(_assistant([_text("Done!")]) + "\n")
    p.feed_line(_result(result="Done!") + "\n")
    p.close()

    res = p.to_result()
    assert p.session_id == "sess-123"
    assert p.raw_lines == 8                      # transcript 忠实记录含垃圾行
    assert len(facts) == 1
    assert facts[0].tool == "Read"
    assert "at1-abc" in facts[0].output
    assert p.tokens == 105 + 1000      # assistant 事件 105 + result.usage 的 1000
    assert res.stop_reason == "end_turn"
    assert res.turns == 3
    assert res.total_cost_usd == 0.0123
    # Handoff 从后向前扫：final_text="Done!" 没有 → 从 assistant 文本块里找到
    assert res.handoff == "已完成：含 at1-abc"
    assert res.is_error is False


def test_heartbeat_every_25_tool_results():
    beats = []
    task = AgentTask(on_heartbeat=beats.append)
    p = StreamParser(task)
    for i in range(30):
        uid = f"t{i}"
        p.feed_line(_assistant([_tool_use(uid, "Bash", {"command": f"echo {i}"})]) + "\n")
        p.feed_line(_tool_result(uid, "ok\n") + "\n")
    p.close()
    assert len(beats) == 1                       # 25 次触发一次，30 次仍只一次
    assert beats[0]["tool_calls"] == 25


def test_result_max_turns_is_not_error():
    p = StreamParser()
    p.feed_line(_result(subtype="error_max_turns", stop_reason="max_turns"))
    p.close()
    res = p.to_result()
    assert res.stop_reason == "max_turns"
    assert res.is_error is False                 # 终态不续跑


def test_result_error_subtype_marks_error():
    p = StreamParser()
    p.feed_line(json.dumps({"type": "system", "subtype": "init", "session_id": "s9"}))
    p.feed_line(_result(subtype="error_during_execution", is_error=True))
    p.close()
    res = p.to_result()
    assert res.stop_reason == "error"
    assert res.is_error is True                  # run() 的续跑候选
    assert res.session_id == "s9"


def test_transcript_writes_every_raw_line_incrementally(tmp_path):
    tp = tmp_path / ".at1" / "transcript.jsonl"
    p = StreamParser(AgentTask(transcript_path=str(tp)))
    p.feed_line("junk-before-json\n")
    p.feed_line(_result())
    assert tp.exists()
    # feed 完即可读（增量 flush，不等会话结束）
    lines = tp.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "junk-before-json"
    assert len(lines) == 2
    p.close()


def test_sanitize_env_strips_controller_secrets(monkeypatch):
    monkeypatch.setenv("AT1_PROVIDER", "glm")
    monkeypatch.setenv("AT1_SECRET_STATE", "ctrl")
    monkeypatch.setenv("LLM_API_KEY", "verifier-key")
    monkeypatch.setenv("BENCHMARK_TOKEN", "bench")

    # solver 自带凭证：本机 ANTHROPIC_* 被剥掉换成 solver 自己的
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://user-local.example/")
    env = _sanitize_env(_mk(api_key="sk-mine"))
    assert "AT1_SECRET_STATE" not in env
    assert "LLM_API_KEY" not in env
    assert "BENCHMARK_TOKEN" not in env
    assert env["ANTHROPIC_BASE_URL"] == "https://open.bigmodel.cn/api/anthropic"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-mine"
    assert env["CLAUDECODE"] == ""               # dcr load-bearing #1
    assert env["IS_SANDBOX"] == "1"              # dcr load-bearing #2

    # solver 无凭证：保留本机 ANTHROPIC_* 配置（selftest 零配置路径）
    env2 = _sanitize_env(_mk(api_key="", base_url=""))
    assert env2.get("ANTHROPIC_BASE_URL") == "https://user-local.example/"


def test_extractors():
    assert extract_handoff("pre <handoff>abc</handoff> post") == "abc"
    assert extract_final_answer("<FinalAnswer>{\"pass\": true}</FinalAnswer>") == '{"pass": true}'
    assert extract_handoff("nothing") == ""


# ── run() 续跑策略 ─────────────────────────────────────────────────────────

def _fake_spawn_factory(outcomes):
    """outcomes: 每次调用返回的 AgentResult 序列。记录 (prompt, resume_session_id)。"""
    calls = []

    def fake(prompt, workdir, solver, task, *, time_box_s=None, max_turns=None,
             claude_bin=None, resume_session_id=None):
        calls.append({"prompt": prompt, "resume": resume_session_id})
        return outcomes[len(calls) - 1]

    return fake, calls


def test_run_resumes_on_error_with_session_id(monkeypatch):
    fake, calls = _fake_spawn_factory([
        AgentResult(session_id="s-res", stop_reason="error", is_error=True, error="api 429"),
        AgentResult(session_id="s-res", stop_reason="end_turn"),
    ])
    monkeypatch.setattr(runner_mod, "spawn_once", fake)
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)   # 不真退避
    res = runner_mod.run("干活", "wd", _mk(), None)
    assert len(calls) == 2
    assert calls[0]["resume"] is None          # 首跑无 resume
    assert calls[1]["resume"] == "s-res"       # 异常后续跑带 session_id
    assert calls[1]["prompt"] == _RESUME_PROMPT  # 续跑提示词
    assert res.resumes == 1


def test_run_does_not_resume_on_terminal_states(monkeypatch):
    # max_turns / timeout / end_turn 都是终态：一次调用即返回，不续
    for terminal in ("max_turns", "timeout", "end_turn"):
        fake, calls = _fake_spawn_factory([
            AgentResult(session_id="s-t", stop_reason=terminal)])
        monkeypatch.setattr(runner_mod, "spawn_once", fake)
        monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)
        res = runner_mod.run("干活", "wd", _mk(), None)
        assert len(calls) == 1, terminal
        assert res.stop_reason == terminal


def test_run_gives_up_without_session_id_or_after_cap(monkeypatch):
    # 异常但没有 session_id → 无法续，直接返回
    fake, calls = _fake_spawn_factory([
        AgentResult(session_id="", stop_reason="error", is_error=True, error="crash")])
    monkeypatch.setattr(runner_mod, "spawn_once", fake)
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)
    res = runner_mod.run("干活", "wd", _mk(), None)
    assert len(calls) == 1 and res.is_error

    # 连续异常超过 MAX_RESUMES 上限 → 停止续跑
    outcomes = [AgentResult(session_id=f"s{i}", stop_reason="error", is_error=True)
                for i in range(runner_mod.MAX_RESUMES + 2)]
    fake2, calls2 = _fake_spawn_factory(outcomes)
    monkeypatch.setattr(runner_mod, "spawn_once", fake2)
    res2 = runner_mod.run("干活", "wd", _mk(), None)
    assert len(calls2) == runner_mod.MAX_RESUMES + 1
    assert res2.resumes == runner_mod.MAX_RESUMES
