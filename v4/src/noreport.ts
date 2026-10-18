/**
 * noreport TS 平移（P2-4）——绝对不报表的 finding 进件预检。
 *
 * 源：legacy-python/src/noreport.py（130 行正则平移，语义逐条对照）。
 * 检察官/法官分工（方案 A）：代码只做「形状即现象」终审（reject）+ 定性公诉（suspect），
 * 不当法官；实害豁免门 0 先于一切——宁可漏拒不可误杀。
 *
 * P2 接线：submit_finding 进件时跑；reject 硬拒不入图（回执给模型可读理由）；
 * suspect 放行入图但回执带公诉意见（提示复核实际影响）。
 */

// 凭证形状（实害豁免判据）
const CRED_RXS = [
	/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
	/\bsk-[A-Za-z0-9_-]{20,}\b/,
	/-----BEGIN [A-Z ]*PRIVATE KEY-----/,
	/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/,
];
const PHONE_RX = /\b1[3-9]\d{9}\b/;
// summary 声明结果类影响。裸"泄露/凭证"不算（"sourcemap 泄露源码"是现象自述）——
// 泄露须搭配敏感对象；凭证/密钥须非否定语境；rce 加拉丁守卫防 sou-rce-map 子串。
const IMPACT_RX =
	/越权|注入|未授权|横向|提权|idor|injection|sqli|unauth|(?<![a-z])rce(?![a-z])|takeover|escalat|(?<![无没])凭证|credential|akia|sk-[a-z0-9]|private.?key|(?<![无没])密钥|(?:泄露|暴露|盗取|窃取|dump|读取|返回|含)[^。\n]{0,10}(?:数据|手机|电话|身份证|姓名|地址|用户|密码|cookie|token|pii|personal|sensitive)|写入|篡改|overwrite|toggle|修改成功|chain|callback|窃取|steal/i;

// 类目信号
const INSTANCE_ID_RX = /\bi-[0-9a-f]{8,17}\b/i;
const PRIVATE_IP_RX =
	/\b(?:(?:10|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;
const CORS_RX = /cors|access-control-allow/i;
const CORS_STAR_RX = /access-control-allow-origin\s*:\s*\*|\*\s*的?\s*cors|cors.{0,20}\*/i;
const VERSION_FP_RX =
	/版本指纹|指纹|version.{0,14}(disclos|leak|fingerprint|reveal)|x-powered-by.{0,30}(disclos|leak|reveal|expos)|server\s+header.{0,20}(disclos|leak|reveal)/i;
const HEADER_MISS_RX =
	/安全头|security.?header|missing.{0,14}header|header.{0,14}miss|(csp|x-frame|hsts|x-content-type|content-security|strict-transport).{0,20}(缺失|missing|absent|not set)/i;
const SOURCEMAP_RX = /sourcemap|source.?mapping|\.js\.map/i;

export interface NoreportInput {
	summary: string;
	evidence?: string;
	endpoint?: string;
}

export interface NoreportVerdict {
	verdict: "reject" | "suspect" | "pass";
	category: string | null;
	reason: string;
}

const PASS: NoreportVerdict = { verdict: "pass", category: null, reason: "" };

function hasRealImpact(input: NoreportInput): boolean {
	if (IMPACT_RX.test(input.summary ?? "")) return true;
	const ev = input.evidence ?? "";
	for (const rx of CRED_RXS) if (rx.test(ev)) return true;
	if (PHONE_RX.test(ev)) return true;
	return false;
}

/** 代码预检。reject=形状即现象终审（硬拒不入图）；suspect=定性公诉（放行+复核提示）；pass=无信号。 */
export function noreportCheck(input: NoreportInput): NoreportVerdict {
	if (hasRealImpact(input)) return PASS;

	const summary = String(input.summary ?? "");
	const blob = `${summary}\n${input.evidence ?? ""}`.toLowerCase();
	const endpoint = String(input.endpoint ?? "");

	// ── 终审类（形状即现象——豁免已过 = 无凭证/PII 跟随）──
	if (endpoint.replace(/\/+$/, "").endsWith(".map")) {
		return {
			verdict: "reject",
			category: "sourcemap",
			reason: "端点即 sourcemap 文件——用它做侦察，报你用它找到的东西",
		};
	}
	if (INSTANCE_ID_RX.test(blob) && (/instance/.test(blob) || /metadata/.test(blob) || summary.includes("元数据"))) {
		return {
			verdict: "reject",
			category: "instance_id",
			reason: "instance-id 是侦察信息无攻击价值——元数据的价值在凭证",
		};
	}
	if (blob.includes("169.254") && (/metadata/.test(blob) || summary.includes("元数据") || summary.includes("169.254"))) {
		return {
			verdict: "reject",
			category: "metadata_endpoint",
			reason: "元数据端点可达但无凭证跟随 = 无影响；元数据的价值在 IAM/RAM 凭证",
		};
	}

	// ── 预检类（定性疑似——公诉意见，可翻案）──
	if (SOURCEMAP_RX.test(summary)) {
		return {
			verdict: "suspect",
			category: "sourcemap",
			reason: "sourcemap 泄露属绝对不报表——除非它是载体，实际报的是用它找到的东西",
		};
	}
	if (PRIVATE_IP_RX.test(summary) && (summary.includes("内网") || summary.toLowerCase().includes("internal"))) {
		return {
			verdict: "suspect",
			category: "internal_ip",
			reason: "内网 IP 泄露属侦察信息——除非证明可达内网目标（SSRF 链）",
		};
	}
	if (CORS_RX.test(summary) && CORS_STAR_RX.test(blob)) {
		return {
			verdict: "suspect",
			category: "cors_wildcard",
			reason: "CORS 配置属绝对不报表——除非证据显示已实际窃取具体敏感数据",
		};
	}
	if (HEADER_MISS_RX.test(summary)) {
		return {
			verdict: "suspect",
			category: "missing_headers",
			reason: "安全头缺失是理论风险，0 元——除非与其他缺陷构成链",
		};
	}
	if (VERSION_FP_RX.test(summary)) {
		return {
			verdict: "suspect",
			category: "version_fingerprint",
			reason: "版本号/中间件指纹是信息收集副产品——除非该版本有已知识别链",
		};
	}
	return PASS;
}
