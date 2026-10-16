/** 通道探针：不带浏览器，纯 pi loop + bigmodel，打印全部事件。 */
import { Agent } from "@earendil-works/pi-agent-core";
import { createChannel, type ChannelMode } from "./channel.js";
import { loadSecrets } from "./secrets.js";

async function main(): Promise<void> {
	const mode = (process.argv[2] === "anthropic" ? "anthropic" : "openai") as ChannelMode;
	const channel = createChannel(mode, loadSecrets());
	console.log(`[probe] mode=${mode} baseUrl=${channel.model.baseUrl}`);
	const agent = new Agent({
		// glm-5.3 始终思考，off → pi 发 thinking:disabled 被 bigmodel 拒（1210）
		initialState: { systemPrompt: "你是测试 worker，用一句中文回答。", model: channel.model, thinkingLevel: "low" },
		streamFn: channel.streamFn,
		getApiKey: async () => channel.apiKey,
	});
	const unsub = agent.subscribe((ev) => {
		if (ev.type === "message_update") {
			const a = ev.assistantMessageEvent;
			if (a.type === "text_delta") process.stdout.write(a.delta);
			return;
		}
		if (ev.type === "message_end") {
			const m = ev.message as any;
			console.log(
				`\n[message_end] role=${m.role} stop=${m.stopReason} usage=${JSON.stringify(m.usage)} err=${m.errorMessage ?? "-"}`,
			);
			return;
		}
		if (ev.type === "agent_end") {
			console.log("[agent_end]", ev.messages.length, "messages");
			return;
		}
		console.log(`[ev] ${ev.type}`);
	});
	try {
		await agent.prompt("回答：1+1=? 只答数字。");
	} finally {
		unsub();
	}
}

main().catch((e) => {
	console.error("[probe] fail:", e instanceof Error ? e.stack : e);
	process.exit(1);
});
