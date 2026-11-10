# P4pre-fix 修复施工计划：P4pre 竣工批判性审查修复批

> **定位**：P4pre 双小批（`1cf8eae` 竣工，148 绿）之后的**验收修复批**。来源=2026-10-23 对竣工结果的批判性审查 + 四项离线实测（真工具+真 catalog 重跑 14 条 query；1304 个 section 行号对账；30k 截断影响面量化；dist 产物核验）。修复批不改 P4pre 的架构决策（LLM 全量卡片/薄工具/CDP HAR/baseline 严门全部保留），只修链路断裂、装配错配、产物陈旧与验收声明与事实的偏差。
> **上游**：`P4pre-知识库与证据批施工计划.md` §7（竣工记录）；`图与基底重构设计.md` §4.6（微纪律住工具描述）/§4.4（工具面）。
> **基线**：`a18551b`（148 绿 + tsc --noEmit 干净）。
> **状态**：✅ 竣工（2026-11-08 施工完成：commit1=`bff8afa` A组 / commit2=`d9b448e` B组 / commit3=`7e3540f` F-7c / commit4=`192674f` C组管线+99篇重跑产物；161 绿 + tsc 干净；F-8 微烟测修前证实预判、修后回归过；唯一留拍项 F-3 preflight 加成按默认"不做"处理）。下一步=真实环境实跑（目标由操作员提供，前置=canary 剧本与通过线成稿）。
> **与 P4 的关系**：零代码交集不变。顺序=P4pre-fix 三组施工 → F-8 微烟测 → **真实环境实跑**（目标后供，canary 剧本届时成稿）→ P4 开工。本地 B 靶 S1 式复跑取消（FD14）。
> **进度引用（2026-11-09）**：真实环境实跑已完成两轮（见 `实机测试任务文档.md`）；本计划核心验收项 F-1/V1 知识双根闭环已按 #454→#455→#456 证据链正式关账（详见 `11-9实机fix.md` §13.3）。**gate 前置满足 ≠ P4 自动开工授权**，开工另行拍板。

---

## 0. 决策点

### 已拍板（2026-10-23 讨论）

| # | 决策 | 内容 |
|---|---|---|
| FD1 | 知识库全局一份，不 per-project 复制 | 知识库保持 `AT-src/knowledge/` 单份（部署自包含，D6 已达成）。否决 per-project 复制案，理由：①复制动作无落点（project 无显式创建时机，assets.db 是首 task 首写时才冒出）；②N 份拷贝=N 个静默过期面（蒸馏回流改全局库后各拷贝全旧，同步无主）；③现目录结构（tasks/ 与 projects/ 平级）下 project 内知识库从 task 出发反而**多**一跳；④隔离性零收益（task 隔离靠 Read 守卫，与知识库位置无关）；⑤"project 冻结当日库版本"的需求由 git 版本承担。"多跳一级太乱"的顾虑在 FD2 后消失——路径由程序解析，模型永远只看到 `knowledge/skills/x.md` |
| FD2 | Read 双根 + offset/limit 行窗口（F-1） | **权限绑物理目录，路径字符串绑约定前缀**。Read 工具加第二允许根（`knowledge/` 前缀 → 对知识库物理根解析 + 包含性校验），参数增可选 offset/limit（1-based 行窗口，输出带行号前缀）。Write 不加 knowledge 分支=结构性只读。机制说明写**工具描述**（微纪律住工具描述），prompt 不加新句——step prompt 引导句管"何时查库"（动机层），工具描述管"怎么读"（机制层） |
| FD3 | 引导句与工具装配同条件 + 寻址去 cwd（F-2） | 引导句只在工具实际装配时渲染；isKnowledgeReady/createSearchKnowledgeTool 寻址从 `process.cwd()` 改模块根（`import.meta.url` 回溯），启动目录不再是隐变量 |
| FD4 | 启动即构建（F-3） | 真机/canary 启动命令固定 `npm run build && node dist/index.js …`，build 前清 dist 消灭孤儿产物。流程性防复发，不依赖人记得 |
| FD5 | formatSearchResults 纪律句删除（F-4a） | 检索结果正文里的"消费纪律"句删除（prompt 引导句 + 工具描述两处保留，第三次每次调用白付 token 且修 Read 前是错误指引） |
| FD6 | planner 侧 search_knowledge 砍除（F-5，修订 D3） | **推翻 D3"双侧装配"，检索消费面=worker 单侧**。planner 无任何读文件工具，检索到也无法精读，最多把技能名写 note（此事 glm-5.3 xhigh 凭自身知识即可）；且与事件驱动快速派 step 的设计相抵。将来若有实证需求再议 |
| FD7 | runSmokeCheck 删假实现换真工具调用（F-6b） | smoke 功能保留（D14 质量门），但实现改为 import 真工具 `executeKnowledgeSearch`——验收证据从此出自生产代码，消灭双份计分逻辑 |
| FD8 | HAR 保留 + 三缺口修（2026-10-24 拍板） | 四项有效能力保留（全流量记录/标准 HAR 1.2/按会话分文件落盘/worker 零感知旁路）；修三缺口=extraInfo 头合并（F-9a）+ 重定向链分条（F-9b）+ 工具描述句修正（F-4b，随 A 组）。**产出路径纪律确认**：固定 `taskDir/evidence/traffic/har/<session_id>.har`，per-session 分文件不合并，随 task 目录归档（tasks/ 已 gitignore 不进仓库），体积双边界（64KB body 截断 × per-session 分文件） |
| FD9 | gen-cards 输入改"全文标题清单 + 前 30k 正文"并重跑 99 篇（F-6a，2026-10-24 拍板） | 程序扫描的**全文标题清单**（extractHeadingsFromMd 现成，5-10KB）+ 前 30k 正文一并喂生成 LLM——section_map 全文档覆盖（深部章节 what 从标题提炼，略浅但"知道有这章+在哪行"到位）；正文阅读成本不变。生成 prompt 补"标题逐字复制原文"句（配合 F-7a 清零错位）。`--force` 重跑 99 篇 + build 重组，纯离线一次性。**注**：30k 只限生成侧造卡的 LLM；运行时 worker 读磁盘原文件永远完整（整读 ≤64KB / offset/limit 翻页无限） |
| FD10 | build 双警告（F-7，2026-10-24 拍板） | ① unmatched-heading 警告清单——模糊兜底命中即报（实测存量 13 错位被"100% 对账"声明掩盖）；② card→catalog stale 检查——gen-cards 末尾自动调 build + mtime 双保险（此类漂移已栽过一次）。静默漂移变有声，~15 行 |
| FD11 | baseline 证据也进哈希（F-10，2026-10-24 拍板） | baseline_evidence 为路径时同算 sha256 存 payload（豁免型"不适用——"无文件不算）。proof−baseline 归因等式两边都贴防篡改封条，~3 行 |
| FD12 | PI-prompt.md 同步收编（F-11，2026-10-24 拍板） | A 组多项修复改变 prompt/工具描述现行文案（Read 描述新增/引导句条件化/planner 句删除/工具输出纪律句删除/submit 描述 HAR 句修正）——PI-prompt.md 是 prompt 现行汇编唯一真相源，A 组落地同批同步。验收=grep 关键句在场+已删句无残留（教训档：报完工前必须 grep 验证） |
| FD13 | F-7c 拍板：D6 源路径标注**落地加行**（2026-10-25；同日实测修订源路径形态） | 26 篇自有 skill 在 **frontmatter 结束行之后**加 `<!-- src: hacker/.claude/skills/<name>/SKILL.md -->`（源侧实测为目录/SKILL.md 形态，27 目录中 distill-report 未入库；脚本判据与连带效应见 F-7c 卡——**加行使行号 +2，必须随即 build 重组 catalog**）。不修订 D6、不划掉。验收=26 篇 grep 全在场，archive/ 73 篇不加 |
| FD14 | 本地 canary 取消，改真实环境实跑（2026-10-25） | B 靶（及旧 A 靶）均不重跑；P4pre canary 不再本地 S1 式复跑，改为**真实环境实跑**——目标由操作员后续提供，时间点=A/B/C 三组施工完成之后。真实环境批前置：①canary 剧本与各观察点通过线成稿（沿用五观察点，通过线逐条定）；②C 组重跑完成（catalog 必须是新卡，否则 30/99 篇深部 section_map 缺失，检索观察数据带污染变量）；③F-1 真机闭环（search_knowledge→Read(offset,limit)）随首跑验证。原"C 组与 canary 并行"的顺序矛盾就此消解 |

### 待拍板

仅一项小项：**F-3 可选加成——preflight dist 新鲜度检查做/不做**（2026-10-25 讨论遗留：主体方案已确认按案施工，加成未表态；默认**不做**=少即是多，若要做开工前说一声即并入 A 组，~5 行）。

### 挂账（下移真实环境批处理，2026-10-25 定）

1. **F-6a 备选方案（分块生成）触发判据**——深部 what 质量多浅算"不满意"无标准，抽 5 篇验收只验覆盖不验质量；
2. **风险⑤重跑后重新对账**——时点与责任人未排；
3. **F-1 真机闭环验收**——挂真实环境首跑（FD14）。

其余 FD1-FD14 已全部拍板（见上表）。

---

## 0.5 施工总规程（施工会话必读——先读完本节再动第一行代码）

### 命令速查（全部在 `AT-src/` 目录执行）

| 动作 | 命令 |
|---|---|
| 全量测试（基线 148 绿，只增不减） | `npm test` |
| 类型检查（必须零输出） | `npx tsc --noEmit` |
| 构建 | `npm run build` |
| 知识库重组 | `node scripts/build-knowledge.mjs` |
| 卡片重生成 | `node scripts/gen-cards.mjs --force` |
| 单篇重生成 | `node scripts/gen-cards.mjs --file <name>` |

### 施工纪律（违反任何一条=返工重做）

1. **只做施工卡里写明的改动**。不顺手重构、不改无关格式、不重命名、不"顺手修"计划外的 bug——发现了就追加到文末"§8 施工发现登记"节，不动手。
2. **一张卡一闭环**：改码 → 加测试 → `npm test` 全绿 → `npx tsc --noEmit` 零输出 → 才能开始下一张卡。
3. **文中行号基于基线 `a18551b`，施工中会漂移**：对不上时按卡内引用的函数名/代码片段语义定位，设计本身不变。
4. **提交节奏**（4 个 commit，在 at1-github 仓库）：commit1=A 组（F-1~F-5+F-11，含 PI-prompt.md 同步）；commit2=B 组（F-9+F-10）；commit3=F-7c（26 篇加源路径行+catalog 重组）；commit4=C 组管线（F-6a/F-6b/F-7a/F-7b）+99 篇重跑产物。F-8 无 commit（纯验证）。commit message 中文一行，风格参照 `git log` 既有条目。
5. **完工打标**：每张卡完成后在该卡标题行尾追加 `✅<commit短hash>`；三组全部完成后文首状态行改"竣工"。
6. **拿不准就停**：现状与施工卡描述冲突（签名不同/测试数不符/命令报错非预期）→ 停下，把冲突写进 `state/status.md` 阻断项等操作员，不擅自改设计。

### 测试落点对应表

| 施工卡 | 新增测试写入 | 参照的现有用例风格 |
|---|---|---|
| F-1 | `test/exec.test.ts` | "路径守卫"/"Read/Write 工具" describe（mkdtempSync 建 taskDir） |
| F-2 | `test/knowledge.test.ts` | 检索 describe |
| F-9 | `test/evidence.test.ts` | "HarRecorder" describe 的 recordCdpEvent 替身注入 |
| F-10 | `test/evidence.test.ts` | "submit_finding 严门回归" describe |
| F-6b/F-7 | 不新增测试文件 | 验收=跑命令看输出 |

---

## 1. 施工卡（A 组：实跑前必修，一次提交）

### F-1 Read 工具双根 + offset/limit 行窗口（FD2）✅bff8afa

**背景**：① 路径守卫 resolveInside 只认 taskDir，search_knowledge 输出的 `knowledge/skills/x.md` 从 taskDir 解析必报"文件不存在"，`../../` 修正又被守卫拒；② Read 只有 path 参数，检索输出里"[L412] 再用 Read(offset,limit) 精读"指向不存在的调用方式；③ 整读 64KB 截断，336KB 长文档后段不可达。148 绿对这条链零覆盖；worker 唯一活路是 Bash sed -n + 猜相对布局，不可靠、浪费回合。

**落点**：`src/tools/exec.ts`（全文 122 行）——resolveInside L20-27（不动）；createReadTool L90-110（parameters 只有 path，execute 直接整读）；READ_MAX_BYTES=64000。

**改动**（全部在 exec.ts，~25 行）：
1. import 区补 `import { fileURLToPath } from "node:url";`。
2. 模块级常量（READ_MAX_BYTES 旁）：
```ts
/** 知识库物理根：src/tools 与 dist/tools 同深度，../../ 均回 AT-src（F-2 同源） */
const KNOWLEDGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../knowledge");
const KNOWLEDGE_PREFIX = "knowledge/";
```
3. 新增私有函数 resolveKnowledgePath(p)：剥前缀 → resolve(KNOWLEDGE_ROOT, rest) → 包含性校验（`abs === KNOWLEDGE_ROOT || abs.startsWith(KNOWLEDGE_ROOT + sep)`，防 `knowledge/../../`）→ 返回 abs；越界 throw `知识库路径逃逸（拒绝）：${p}`。
4. createReadTool 改造：
   - parameters 增 offset/limit（均 Type.Optional(Type.Number())，description 分别"1-based 起始行号""读取行数，默认 100"）；
   - execute：abs = path.startsWith(KNOWLEDGE_PREFIX) ? resolveKnowledgePath(path) : resolveInside(taskDir, path)；存在性/是否文件两检查照旧；
   - **行窗口分支**（offset 或 limit 任一给出）：全文读入按 `/\r?\n/` 切行；offset=Number(params.offset)||1，limit=Number(params.limit)||100；offset>总行数 → throw `offset 超出文件末尾（共 ${N} 行）`；输出首行 `L${start}-L${end}（全文 ${N} 行）`，正文每行 `L${n}| ${line}`（cat -n 风格）；
   - 未给两参：整读 64KB 截断现状一字不动（evidence 小文件场景）；
   - description 改：`读文件。task 内相对路径（如 evidence/probe.txt）；知识库文件用 knowledge/ 前缀（如 knowledge/skills/ad-attacks.md）。默认整读（超 64KB 截断）；长文件给 offset/limit 按行窗口读（1-based 行号，输出带行号前缀，如 offset=412 limit=50）。`；
   - **Write/Bash 零改动**（worker 对知识库结构性零写面）。

**边界**（已拍板）：`knowledge/` 是保留前缀，taskDir 内同名子目录会被劫持到全局库——概率≈0（worker 只写 evidence/），接受。search_knowledge 输出零改动即闭环。

**测试**（test/exec.test.ts 新 describe"Read 双根与行窗口"，读仓库内真文件）：
1. `knowledge/skills/ad-attacks.md` 无窗口整读成功（断言含正文任一关键词）；
2. 同文件 offset=1 limit=3 → text 含 `L1-L3` 与 `L1|`；
3. `knowledge/../../package.json` → rejects.toThrow(/逃逸/)；
4. offset=999999 → rejects.toThrow(/末尾/)；
5. 现有"路径守卫"与"Read/Write 工具"用例不动且全绿 = taskDir 行为不变的证明。

**验收命令**：`npx vitest --run test/exec.test.ts && npx tsc --noEmit`
**真机闭环**：挂真实环境首跑（FD14 挂账③）。
**禁止**：不动 resolveInside 本体；不动 Write/Bash；不新增依赖。

### F-2 引导句条件渲染 + 知识库寻址去 cwd（FD3）✅bff8afa

**背景**：引导句"不熟的漏洞类…先 search_knowledge 查章节地图再按行号精读"在 worker step prompt 无条件渲染（agent.ts L138），工具注册却在 isKnowledgeReady() 条件后（agent.ts L178）——该函数查 `process.cwd()/knowledge/catalog.json`，取决于进程从哪个目录启动。装配失败时 prompt 仍教模型调不存在的工具——静默错配，排查时会错怪模型。

**落点**：`src/agent.ts`——renderStepPrompt L119（已导出，签名 (step, situational, standardsIndex?)）、引导句 L138、调用点 L245、工具装配 L178-186；`src/tools/knowledge.ts`——isKnowledgeReady L228-231（process.cwd()）、createSearchKnowledgeTool L233-235（knowledgeDir 默认 process.cwd()/knowledge）。planner 侧两处不用动——F-5 直接删除。

**改动**（~6 行）：
1. knowledge.ts：文件头补 `import { fileURLToPath } from "node:url";`（dirname 已有）；模块级 `const KNOWLEDGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../knowledge");`；isKnowledgeReady 的默认路径改 `join(KNOWLEDGE_ROOT, "catalog.json")`（customPath 参数保留不动）；createSearchKnowledgeTool 的 `opts.knowledgeDir ?? KNOWLEDGE_ROOT`。与 F-1 的 exec.ts 同源同深度（src/tools 与 dist/tools 的 ../../ 都是 AT-src，tsconfig rootDir=src/outDir=dist 已核实）。
2. agent.ts：renderStepPrompt 增第 4 参 `knowledgeReady = false`（默认 false=不渲染，安全侧）；L138 那行改为 `...(knowledgeReady ? ["不熟的漏洞类/绕过手法/中间件打法，先 search_knowledge 查章节地图再按行号精读。"] : [])`；调用点 L245 改 `renderStepPrompt(step, situational, standardsIndex, isKnowledgeReady())`；工具装配处（L178）不变——两处从此用同一函数同一条件。

**测试**（test/knowledge.test.ts 新 describe"引导句条件渲染"）：
```ts
import { renderStepPrompt } from "../src/agent.js";
const step = { id: 1, kind: "step", payload: JSON.stringify({ summary: "探测" }) } as any;
it("knowledgeReady=false → 无引导句；true → 有", () => {
  expect(renderStepPrompt(step, {} as any, undefined, false)).not.toContain("search_knowledge");
  expect(renderStepPrompt(step, {} as any, undefined, true)).toContain("search_knowledge");
});
```
（renderStepPrompt 内部只用 JSON.parse(step.payload) + JSON.stringify(situational)，{} mock 安全；vitest 不做类型检查。）

**验收命令**：`npx vitest --run test/knowledge.test.ts`；去 cwd 验证（build 后任意目录）——`cd %TEMP% && node -e "import('file:///D:/Downloads/hacker/at1-github/AT-src/dist/tools/knowledge.js').then(m=>console.log(m.isKnowledgeReady()))"` 应打印 true（Windows cmd）。注意：**不要**在 vitest 里用 process.chdir 验证（threads 模式 chdir 是进程级，会污染并行测试）。
**禁止**：不动 planner.ts/planner-prompt.ts（那是 F-5 的活）；isKnowledgeReady 的 customPath 参数保留。

### F-3 启动即构建 + 清理孤儿产物（FD4）✅bff8afa（preflight 加成未做，按默认）

**原因**：项目有三条互不相干的路径，P4pre 验收只走了后两条——

```
npm run build     → tsc 产出 dist/（真机 node dist/index.js 执行的就是它） ← 最后一次 10-22 18:06，早于 har.ts/knowledge.ts 落地
npx tsc --noEmit  → 只做类型检查，不写任何文件
vitest --run      → 直接跑 src/（自有转译管线），从头到尾不碰 dist/
```

竣工时 dist 停在旧状态（缺 `dist/har.js`、`dist/tools/knowledge.js`），`dist/` 又在 .gitignore 里，git 不会提醒。伴生问题：tsc 从不清理已删源文件的产物，`dist/tools/submit-fact.js`（10-16 僵尸）滞留至今。

**后果**：直接上真机时，`node dist/index.js` 跑的是**没有 P4pre 的旧程序**——search_knowledge / HAR 旁路 / baseline 严门全部不存在，且**零报错**，程序正常启动正常跑。测试全绿（vitest 对着 src，测的确实是新代码）与产物可启动（dist 旧代码）互不覆盖——以为在测新功能，实际跑的是旧程序。审查时已手动 `npm run build` 补齐，本卡是流程防复发。

**方案**（主体已拍板，FD4 + 2026-10-25 确认按案施工）：`package.json` scripts 两处改（唯一改动文件）：
```jsonc
"build": "node -e \"require('fs').rmSync('dist',{recursive:true,force:true})\" && tsc -p tsconfig.json",
"run": "npm run build && node dist/index.js run",
```
- build 前 rmSync 清 dist（零新依赖——不用 rimraf；`node -e` 默认按 CJS 解析，require 可用，package.json 的 type:module 不影响 -e）；孤儿产物从此不可能滞留；
- `run` 脚本：用法 `npm run run -- <task> [--max-rounds=N] [--budget-min=N] [--no-browser]`（npm 把 `--` 后参数追加到脚本末尾，落点正确）；
- 真机/实跑启动一律走 `npm run run -- <task>`，不再裸跑 `node dist/index.js`；smoke/smoke:block 脚本不动。
可选加成（**未拍板，默认不做**，见 §0 待拍板）：preflight 增 dist 新鲜度检查（src 最新 mtime 晚于 dist → 硬失败人话报错）作双保险。

**验收命令**（顺序执行）：
```
npm run build && ls dist/tools/knowledge.js && ls dist/har.js
ls dist/tools/submit-fact.js   # 期望：No such file（僵尸产物已清）
```
**禁止**：不动 tsconfig；不新增 npm 依赖（rimraf 等）；不改 index.ts 代码（纯 package.json 卡）。

### F-4 知识工具文案两处修正（FD5 + HAR 描述句）✅bff8afa

**F-4a formatSearchResults 纪律句删除**

- **背景**："先查地图再 Read(offset,limit) 精读"共三处——step prompt 引导句（agent.ts L138，F-2 条件化）+ 工具 description（knowledge.ts L256，保留）+ **每次检索结果正文首行**（knowledge.ts L206）。第三处时机错误（模型已拿到结果再教怎么用=无效重复），且修 Read 前是错误指引，每次白付 ~30 token。
- **改动**：删 knowledge.ts L206 整行 `lines.push("（消费纪律：…）\n")`。前两处保留（动机层引导+机制层自描述，分工不重复）。
- **验收**：`grep -n "消费纪律" src/tools/knowledge.ts src/agent.ts` → 只剩 description 一处（L256 附近，内容含"先查地图再按行号精读"）；结果正文 formatSearchResults 输出不再含该句（现有检索测试若断言该句需同步删断言）。

**F-4b submit_finding 工具描述的 HAR 路径句修正**

- **背景**：HAR 在会话 dispose() 才落盘，worker 会话内 submit_finding 时文件还不存在；描述却引导 baseline_evidence 填 `evidence/traffic/har/` 路径（submit.ts L88 与 L104-107 两处），严门 rule 2 存在性检查必打回——浪费回合+困惑。HAR 真实消费者是会话后操作员审计，不是会话内 worker。
- **改动**：两处 description 替换为逐字新文案——
  L88（description 数组内那行）：`"- baseline_evidence：对照证据文件相对路径（evidence/ 下，建议 evidence/baseline-*.txt），或显式豁免 '不适用——<一句话原因>'。proof=攻击条件在场（带 payload/受害者 ID）的请求；baseline=同端点去除攻击条件的请求——两者相减差异才能归因。写不了对照就写清楚为什么不适用；（evidence/traffic/har/ 是平台事后审计面，会话内尚未落盘，不要填）",`
  L104-107（参数 description）：`"对照证据文件相对路径（evidence/ 下），或显式豁免 '不适用——<一句话原因>'。必填，值二选一"`
- **验收**：`grep -n "traffic/har" src/tools/submit.ts` → 仅剩否定句一处（"不要填"句内）；evidence.test.ts 严门用例全绿（严门逻辑本身零改动）。

**禁止**：不动 validateBaselineEvidence 三规则；不动 baseline_note 参数。

### F-5 planner 侧 search_knowledge 砍除（FD6，修订 D3）✅bff8afa

**背景**：planner 工具面无任何读文件工具，检索到卡片也无法精读，最多把技能名写 note（glm-5.3 xhigh 凭自身知识即可）；每次唤醒多一句引导+工具面多一项+0 命中账本多一个来源，预期使用率≈0，纯成本。

**落点与改动**（精确三处删除，零新增）：
1. `src/planner.ts` L23：删 `import { createSearchKnowledgeTool, isKnowledgeReady } from "./tools/knowledge.js";` 整行（确认文件内无其他使用处后删 import，有则只删用不到的那个名字）；
2. `src/planner.ts` L313-315：删 `if (isKnowledgeReady()) { tools.push(createSearchKnowledgeTool({...})); }` 三行；
3. `src/planner-prompt.ts` L65：删引导句整行（含尾逗号）。
worker 侧全保留。设计稿 D3 修订：检索消费面=worker 单侧。

**验收命令**：
```
grep -n "knowledge" src/planner.ts src/planner-prompt.ts   # 期望：零输出
npm test && npx tsc --noEmit
```
**禁止**：不动 agent.ts 的 worker 侧装配；不动 knowledge.ts。

### F-11 PI-prompt.md 同步收编（FD12，随 A 组同批提交）✅bff8afa

**背景**：A 组多项修复改变 prompt/工具描述现行文案，`docs/PI-prompt.md` 是 prompt 现行汇编唯一真相源，不同步则文档与现实分叉，后续调优失去基线。

**改动**（A 组代码落地后、commit1 前同批）：更新 docs/PI-prompt.md 五处——
1. Read 工具描述 → F-1 新文案（含 knowledge/ 前缀与 offset/limit 用法）；
2. worker step prompt 现行全文 → 引导句处加条件渲染说明（"装配 knowledge 时才有该句"）；
3. planner 态势导读 → 删知识库引导句后的现行全文；
4. search_knowledge 工具描述（不变）与检索结果示例（删消费纪律句后的形态）；
5. submit_finding 工具描述 → F-4b 新文案。

**验收命令**（全部通过才算完，教训档：报完工前必须 grep，勿口头汇报）：
```
grep -c "offset" docs/PI-prompt.md            # ≥1（Read 新描述在场）
grep -c "knowledge/" docs/PI-prompt.md        # ≥1
grep -n "不熟的漏洞类" docs/PI-prompt.md      # 仅 worker 侧一处（planner 处已删）
grep -n "traffic/har" docs/PI-prompt.md       # 仅否定语境（"不要填"）或零命中
```
**禁止**：不改 PI-prompt.md 里与 A 组无关的章节。

---

## 2. 施工卡（B 组：HAR 保真——微烟测前后验证 + 修复 + baseline 哈希）

### F-8 HAR 微烟测（验证与验收卡，30 分钟，无靶标，无 commit）✅（修前/修后各跑一次，注记：修前125条entries全无Cookie头+重定向中间跳全丢(预判证实，本地确定性靶标Set-Cookie→302链+github.com 301真链)；修后回归过——11条含Cookie头(含github真实_gh_sess会话Cookie)、301→302→200三跳逐跳齐、307 redirectURL 正确；body空置9/127含设计留空的3xx跳）

**目的**：Cookie 头缺失与重定向断链是基于 CDP 事件结构的预判，未在本机实证。修前跑一次证伪/证实（若 Cookie 实际在场则 F-9a 免修——少即是多）；修后必跑作回归验收。

**操作**（不依赖完整 agent loop，临时脚本直起浏览器）：
1. `npm run build`；
2. 写临时脚本 `scripts/tmp-har-smoke.mjs`（用后删，不进 git）：
```js
import { BrowserPool } from "../dist/browser-pool.js";
import { BrowserSession } from "../dist/tools/browser.js";
import { mkdtempSync } from "node:fs"; import { join } from "node:path"; import { tmpdir } from "node:os";
const dir = mkdtempSync(join(tmpdir(), "har-smoke-"));
const pool = await BrowserPool.start(dir);
const s = new BrowserSession(pool.endpoint, join(dir, "evidence", "traffic", "har", "smoke.har"));
const page = await s.page();
await page.goto("http://httpbin.org/cookies/set/foo/bar", { waitUntil: "networkidle" }); // Set-Cookie→302→回传 Cookie 一步全验
await page.goto("http://github.com", { waitUntil: "networkidle" }).catch(() => {});      // http→https 301 链
// 清理调用照抄 src/agent.ts finally 块对 session/pool 的写法（dispose/shutdown 按现有 API）
```
   注意：import 路径以 `ls dist` 实际产物为准（BrowserSession 若从 src/tools/browser.ts 导出则 ../dist/tools/browser.js）；BrowserPool.start 参数与 session 清理写法**照抄 src/agent.ts 现有调用**，不自造。
3. 跑 `node scripts/tmp-har-smoke.mjs`，打开产物 HAR 核三点：
   - ① `/cookies` 请求的 request.headers 含 `Cookie: foo=bar`（修前预判没有，修后有）；
   - ② 302 链逐跳成 entry：httpbin 的 set→302→/cookies 两跳、github 的 301→https 两跳（修前只剩最终跳）；
   - ③ response body 空置率（观察项，不修）。
4. httpbin.org 不通时的替代靶标：任意短链服务（bit.ly 等）验 302 链；Cookie 项可暂缺并在卡尾记录"未验证"，不阻塞。
5. 结果记入本卡标题行 ✅ 注记（修前/修后各跑一次）；删临时脚本。

**禁止**：不把临时脚本 commit 进仓库；不改 browser-pool/browser 源码（那是 F-9 的事）。

### F-9 HAR 保真修复（FD8 已拍板，~50 行 + 替身测试）

#### 数据结构前置改动（两修共用，`src/har.ts`）

现状：`entries: Map<string, InFlightEntry>`（在飞）+ `completed: InFlightEntry[]`——onLoadingFinished/onLoadingFailed 时条目移入 completed 并从 Map 删除。extraInfo 事件可能在条目"完成后"才到（CDP 不保证顺序），没有全生命周期索引就合并不进。

**改动**：HarRecorder 类内增两字段：
```ts
private byId = new Map<string, InFlightEntry>();                     // 全生命周期索引（在飞+已完成）
private pendingExtra = new Map<string, { req?: any; resp?: any }>(); // 早到 extraInfo 暂存
```
维护点仅两处：onRequestWillBeSent 建/换条目时 `this.byId.set(reqId, entry)`；flush() 内（置 flushed 后）`this.byId.clear(); this.pendingExtra.clear();`（孤儿丢弃、内存有界）。其余生命周期方法零改动。内存可忽略（条目本就在 completed，只多指针）。

#### F-9a extraInfo 头合并（~25 行）✅d9b448e

**背景**：CDP 把一次请求拆两个事件——requestWillBeSent=骨架（URL/方法/多数头），requestWillBeSentExtraInfo=网络层真实发包头（**Cookie、部分 Authorization**）；响应侧 responseReceivedExtraInfo 携带 Set-Cookie。现代码只听骨架（browser.ts L44-62）→ HAR 所有请求无 Cookie 头：身份归因核心缺失，越权证明无法自证，curl -b 无法重放同身份。

**落点**：`src/tools/browser.ts` L44-62 事件挂载区；`src/har.ts`（新方法 + onRequestWillBeSent 尾部回捞）。

**改动**：
1. browser.ts 事件区增两行（骨架监听之后）：
```ts
this.cdpSession.on("Network.requestWillBeSentExtraInfo", (p) => this.recorder.onRequestExtraInfo(p));
this.cdpSession.on("Network.responseReceivedExtraInfo", (p) => this.recorder.onResponseExtraInfo(p));
```
2. har.ts 新增两个公开方法 + 一个模块级私有函数 mergeHeaders(base: HarHeader[], extra: any): HarHeader[]：
   - 实现：extra 的头**跳过 ":" 开头伪头**（:authority/:method 等，非 HAR 语义）→ 头名 toLowerCase 归一 → 与 base 合并，**extraInfo 同名头覆盖 base**（extraInfo=网络层真实值，权威）→ 返回新数组；
   - onRequestExtraInfo(params)：id=params.requestId；查 byId 命中 → `e.requestHeaders = mergeHeaders(e.requestHeaders, params.headers)`；未命中 → 暂存 `pendingExtra.set(id, {...旧值, req: params})`（**extraInfo 早于骨架到达是 CDP 常态**）；
   - onResponseExtraInfo(params)：同型，resp 侧 → `e.responseHeaders = mergeHeaders(...)`；未命中同样暂存；
3. onRequestWillBeSent 建完条目后：查 pendingExtra.get(reqId)，命中则回捞两次 merge 进 requestHeaders/responseHeaders，再 pendingExtra.delete(reqId)；
4. recordCdpEvent 的 switch 增两个 case："Network.requestWillBeSentExtraInfo" / "Network.responseReceivedExtraInfo"（替身测试通道，与现有四 case 同风格）。
时序依据：CDP 同 session 事件按到达序投递，extraInfo 归属"该 requestId 当前最新条目"；重定向下 A 跳 extraInfo 先于 B 跳骨架到达，按序归属正确（Playwright HAR 同款策略）。

**测试**（test/evidence.test.ts 的 HarRecorder describe 内，全部走 recordCdpEvent 注入）：
1. 骨架先到→extraInfo 后到：requestHeaders 含 Cookie，同名头被 extraInfo 值覆盖；
2. extraInfo 先到→骨架后到（回捞路径）：同样合并成功；
3. 伪头 ":method" 不出现在最终 headers；
4. 孤儿 extraInfo（无对应骨架）注入后 flush 不崩、不进产物；
5. responseReceivedExtraInfo 的 Set-Cookie 进 responseHeaders。

**验收命令**：`npx vitest --run test/evidence.test.ts && npx tsc --noEmit`；F-8 修后跑核①（Cookie 在场）。
**禁止**：不动 Network.enable 参数（5MB 缓冲边界是观察项）；不动 getResponseBody/body 逻辑。

#### F-9b 重定向链分条（~20 行）✅d9b448e

**背景**：CDP 对重定向**复用同一 requestId**——A→302→B 时 requestWillBeSent 带同一 id 再发一次（内容为 B），A 的完整响应放在参数 redirectResponse 字段捎带。现代码收到第二次事件直接 `entries.set` 覆盖旧条目（har.ts L112 附近）→ A 跳的请求（含 Cookie/POST body）与响应全丢：HAR 里 A→302→B→302→C 只剩 C，而丢失的 A 跳常是登录提交（302 多发生在 POST 后），恰是最需要证据的那条。

**落点**：`src/har.ts` onRequestWillBeSent 开头（骨架解析之前）。

**改动**：onRequestWillBeSent 在建新条目前插入：
```ts
// F-9b：重定向复用 requestId——旧在飞条目按 A 跳终态落 completed
const prev = this.entries.get(reqId);
const rd = params.redirectResponse;
if (prev && rd) {
  prev.status = Number(rd.status ?? 302);
  prev.statusText = String(rd.statusText ?? "");
  prev.protocol = String(rd.protocol ?? prev.protocol);
  prev.mimeType = String(rd.mimeType ?? prev.mimeType);
  prev.responseHeaders = Object.entries(rd.headers ?? {}).map(([k, v]) => ({ name: k, value: String(v) }));
  prev.endTimestamp = Number(params.timestamp ?? prev.startTimestamp);
  // body 留空（3xx body 无证据价值）；redirectURL 取 Location 头：
  // buildHar 侧 response.redirectURL 现为硬编码 ""——改为条目级字段 redirectUrl?: string，此处填 rd.headers.location
  this.completed.push(prev);
  this.entries.delete(reqId);
}
```
配套两小处：InFlightEntry 增可选字段 `redirectUrl?: string`；buildHar 的 response.redirectURL 从 `""` 改 `e.redirectUrl ?? ""`。之后按现状建 B 跳新条目（entries.set + byId.set 同步换新）。loadingFinished/getResponseBody 零改动——链尾只触发一次，取最终跳 body，天然正确。多跳链逐跳递归适用（每跳终态来自下一跳的 redirectResponse）。

**测试**（evidence.test.ts HarRecorder describe，recordCdpEvent 注入）：
1. A(带 Cookie 头)→302(redirectResponse)→B→200：flush 产物恰好 2 条 entry，A=302+redirectURL+Cookie 在，B=200；
2. 三跳链 A→B→C：3 条 entry 逐跳齐全；
3. 无 redirectResponse 的普通请求：现有用例全绿=零行为变化。

**验收命令**：`npx vitest --run test/evidence.test.ts`；F-8 修后跑核②。
**禁止**：不动 loadingFinished/onLoadingFailed；不动 body 截断逻辑。

#### 产出路径纪律（FD8 用户要求确认，零代码）

产出固定 `taskDir/evidence/traffic/har/<session_id>.har`：per-session 分文件不合并；随 task 目录整体归档；`tasks/` 在 .gitignore，不进仓库；体积双边界（64KB body 截断 × per-session 分文件）。观察项（不预设机制）：长 task 会积累数十个 session HAR，无清理策略——canary 实测量级，膨胀再议（如仅保留有 finding 关联的 session）。

**明确不修（观察项）**：① body 逐出——`maxResourceBufferSize` 5MB 上限下资源多的页面旧 body 被挤掉（`browser.ts:38`），渗透关心 API 响应不关心图片；② dispose 时在飞的 getResponseBody 竞态丢一两个 body——影响极小。

### F-10 baseline 证据哈希（FD11，~3 行）✅d9b448e

**背景**：evidence_sha256 只对 proof 的 evidence 计算（graph.ts submitFinding 内 `const sha = hashEvidence(taskDir, payload.evidence)`，约 L266），baseline_evidence 指向的对照文件不进哈希——翻案/复测时可替换对照文件而图内无感知，proof−baseline 归因的后半边裸奔。

**落点**：`src/contracts.ts` FindingPayload（z.object）；`src/graph.ts` submitFinding。

**改动**（两文件各一处）：
1. contracts.ts FindingPayload 增一行字段：`baseline_sha256: z.string().optional(),`——**必须显式加**：zod 默认 strip 未知键，不加的话 graph.ts 塞进去也会在 FindingPayload.parse 时被剥掉；
2. graph.ts submitFinding 在 `const sha = hashEvidence(...)` 之后：
```ts
if (!payload.baseline_evidence.startsWith("不适用——")) {
  payload.baseline_sha256 = hashEvidence(taskDir, payload.baseline_evidence);
}
```
（豁免型不算；路径型此时文件必存在——严门 rule 2 已先行验证，不加 try/catch，若崩说明严门漏了，显性更好。）

**测试**（test/evidence.test.ts "submit_finding 严门回归" describe 内加一用例）：构造路径型 baseline 提交成功后，`JSON.parse(db.prepare("SELECT payload FROM nodes WHERE kind='finding'").get().payload)` 含 `baseline_sha256` 且为 64 位 hex；豁免型提交的 payload 无该键。

**验收命令**：`npx vitest --run test/evidence.test.ts && npx tsc --noEmit`
**禁止**：不动 evidence_sha256 列与 INSERT 语句（新哈希只进 payload JSON）；不动 validateBaselineEvidence。

---

## 3. 施工卡（C 组：离线管线，不阻塞 A/B 组施工，但须先于真实环境批完成）

### F-6a gen-cards 输入改"全文标题清单 + 前 30k 正文"（FD9）✅192674f

**背景**：生成输入=文档前 30,000 字符（gen-cards.mjs L183 `mdContent.slice(0, 30_000)`），实测 99 篇中 **30 篇超 30k**（injection-deser 62% 标题在截断线后 / logic-race 78% / crypto-attacks 71% / offensive-windows-mitigations 92%——511KB 只看到前 6%）；卡片中来自 30k 之后的章节数=0（全部 30 篇无一例外）。worker 查深部概念→卡片命中但 section_map 无行号→退回手动 grep；兜底全文扫描救不了（仅 99 卡全零分时触发）。

**落点**：`scripts/gen-cards.mjs`——L183-184（输入构造与 prompt 调用，在 callLlmForCard 内）；SYSTEM_PROMPT（L43 起）。

**改动**：
1. 文件头补 `import { extractHeadingsFromMd } from "./build-knowledge.mjs";`（已核实 build-knowledge L225 有 main 守卫，import 无副作用）；
2. L183-184 改为：
```js
const headings = extractHeadingsFromMd(mdContent);
const tocLines = headings.map((h) => `L${h.line} ${"#".repeat(h.level)} ${h.text}`).join("\n");
const truncated = mdContent.slice(0, 30_000);
await agent.prompt(
  `请阅读以下安全技能文档并输出检索卡 JSON：\n\n【全文标题清单（行号+标题，已覆盖全文）】\n${tocLines}\n\n【正文（前 30000 字符）】\n${truncated}`,
);
```
3. SYSTEM_PROMPT 的 section_map 准则处补两句：`section_map 的 heading 必须逐字复制原文标题（含编号与标点，禁止改写/翻译/去编号）——标题清单已覆盖全文，重要章节即使不在正文截断段内也应入图（what 可从标题提炼一句话）。`
4. 正文照旧只喂前 30k（省 token 不变），目录喂全文；深部 what 从标题提炼，精度略降但"知道有这章+在哪行"到位。

**跑批**（C 组代码改完后一次性）：`npm run build && node scripts/gen-cards.mjs --force --concurrency 3`（断点续跑+指数退避已有；几十分钟）→ `node scripts/build-knowledge.mjs` 重组 catalog。

**验收**：抽 5 篇长文档（injection-deser/logic-race/crypto-attacks/offensive-windows-mitigations/offensive-basic-exploitation）——打开其 cards/<name>.json，抽尾部 2-3 个章节标题反查 section_map 有对应条目；F-7a 警告清单清零或逐条可解释；smoke（F-6b 真实现）扫视不回退。
备选（不推荐，触发判据挂账真实环境批）：>30k 文档分块多次调用合并，成本 3-5 倍，收益仅深部 what 更准。
**禁止**：不动 cards schema/normalizeCardJson；不动重试与并发逻辑。

### F-6b runSmokeCheck 换真实现（FD7）✅192674f

**背景**：gen-cards 末尾 smoke 打分器（gen-cards.mjs L302-344）是手抄简化副本——空格分词、无中文 bigram、计分与真工具不同。已发生事故：竣工记录 §7.2 的 smoke 出自副本，SSRF query top1 记成 open-redirect/waf-bypass（错），真工具实测 offensive-ssrf:53 第一（对）。两份计分逻辑=永久漂移源。

**落点**：`scripts/gen-cards.mjs` runSmokeCheck 函数（L302-344 整段替换）+ main 末尾调用处。

**改动**：
1. 删手抄计分体（L302-344 函数体）；
2. 新实现（mjs 纯 node 不能 import TS，动态 import dist 产物）：
```js
async function runSmokeCheck() {
  console.log("--- 10 条 Smoke Query 扫视（真工具 executeKnowledgeSearch）---");
  let m; try { m = await import("../dist/tools/knowledge.js"); } catch {
    console.warn("! dist/tools/knowledge.js 不可用，先 npm run build 再跑 smoke；本次跳过"); return;
  }
  const catalog = JSON.parse(readFileSync(join(KNOWLEDGE_DIR, "catalog.json"), "utf-8"));
  for (const q of SMOKE_QUERIES) {
    const { results } = m.executeKnowledgeSearch(q, catalog, join(KNOWLEDGE_DIR, "skills"));
    console.log(`\nQuery: [${q}] -> 命中 ${results.length} 篇`);
    for (const r of results.slice(0, 2)) console.log(`  - [得分 ${r.score}] ${r.name}: ${r.use_when}`);
  }
}
```
   （KNOWLEDGE_DIR/常量名以 gen-cards.mjs 现有 SKILLS_DIR 等推算，保持同源；main 末尾调用改 `await runSmokeCheck()`。）
3. 执行顺序约定：main 末尾 = buildKnowledge()（F-7b 新增）→ runSmokeCheck()——smoke 永远用刚重组的新 catalog。

**验收**：`npm run build && node scripts/gen-cards.mjs --file ad-attacks`（单篇轻跑触发 smoke）→ 输出中 `SSRF bypass cloud metadata` 的 top1=offensive-ssrf（与真工具实测一致）。
**禁止**：不删 SMOKE_QUERIES；不新抄计分逻辑。

### F-7 build-knowledge 双警告（FD10，卫生级）✅192674f

**F-7a unmatched-heading 警告**

- **背景**：matchHeadingLine 四层兜底永不失败（精确→包含→token 重叠→正文搜索→return 1），规范化差异（em-dash、U+2011、LLM 改写编号）静默落错行。实测 1304 sections **13 个错位（99.0%）**，竣工记录"100% 对账"与事实不符；错位行号把 worker 精读窗口带偏，且无告警。
- **落点**：`scripts/build-knowledge.mjs`——matchHeadingLine L70-110；调用点 L188；buildKnowledge L124。
- **改动**：
  1. matchHeadingLine 返回值从 number 改为 `{ line: number; tier: "exact" | "contains" | "tokens" | "text" | "none" }`（五层各自 return 处标注 tier；return 1 的两处="none"）；
  2. 调用点（L188）同步解构；buildKnowledge 循环内收集 `tier !== "exact"` 的条目到 `warnings` 数组（元素：`{name, heading, line, tier}`）；
  3. buildKnowledge 返回值增 `warnings` 字段（与 count/stale 并列）；main 尾部打印：`! ${warnings.length} 个 heading 非精确对齐（tier 清单）`（stderr，build 不失败）；
  4. 全仓 grep `matchHeadingLine` 同步其余调用点（若有测试引用则更新断言）。
- **验收**：当前语料跑 `node scripts/build-knowledge.mjs` → 警告数 ≈ 13（重跑前口径）；F-6a 重跑后清零或逐条可解释（重跑后按 F-7a 口径重新对账——时点/责任人挂账真实环境批）。
- **禁止**：不改四层匹配逻辑本身（只加标记，不动算法）；警告不导致 exit 1。

**F-7b card→catalog stale 检查**

- **背景**：mtime 检查只盖 md→card；card→catalog 无检查；gen-cards 跑完不自动 build。重生成忘 build → 运行时用旧 catalog 零告警（catalog 有前科）。
- **落点**：`scripts/gen-cards.mjs` main 末尾；`scripts/build-knowledge.mjs` buildKnowledge 开头。
- **改动**：
  1. gen-cards.mjs：F-6a 已引入 `import { extractHeadingsFromMd } from "./build-knowledge.mjs"`，同处补 buildKnowledge 名字；main 末尾 runSmokeCheck 之前：`const res = buildKnowledge(); console.log(\`✓ catalog 已重组：${res.count} 篇\`);`——buildKnowledge throw 则让它自然抛出中断（catalog 坏时 smoke 无意义）；
  2. build-knowledge.mjs buildKnowledge 开头：若 catalog.json 存在，取其 mtime 与全部 card mtime 对比，catalog 旧于任一 card → 收集进返回值 `staleCatalog` 数组（与 md→card 的 stale 同风格打印警告）——独立跑 build 时的双保险。
- **验收**：改一张 cards/*.json 后只跑 `node scripts/gen-cards.mjs --file <name>` → catalog 自动同步（mtime 变新）；`node scripts/build-knowledge.mjs` 单独跑时能报出人工改卡不 build 的 stale。
- **禁止**：不自动改写 card/md 内容。

### F-7c（顺手，1 个脚本）D6 源路径标注落地（FD13 已拍板：加行）✅7e3540f

**背景**：D6 拍板"26 自有 skill 头部标注源路径"未实施（privesc-linux.md 等直接 frontmatter 开头）——hacker→AT-src 单向快照的溯源约定空转，两侧漂移无法对账。

**已核实事实**（2026-10-25 实测）：源侧 `D:/Downloads/hacker/.claude/skills/` 下是 **27 个目录**（每个含 SKILL.md），其中 `distill-report` 未入知识库 → **26 篇对应**；目标侧 `AT-src/knowledge/skills/<name>.md` 同名存在；**源路径形态是 `<name>/SKILL.md`**（FD13 初稿写 `<name>.md` 不准确，以本卡为准）；73 篇 Claude-Red 语料无源路径，不加。

**改动**（临时脚本一次跑完，脚本本身不 commit；本卡单独 commit3）：
```js
// scripts/tmp-add-src.mjs（用后删）
import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
const SRC = "D:/Downloads/hacker/.claude/skills";
const DST = "D:/Downloads/hacker/at1-github/AT-src/knowledge/skills";
for (const name of readdirSync(SRC)) {
  const dst = `${DST}/${name}.md`;
  if (!existsSync(dst)) { console.log(`- 跳过（未入库）: ${name}`); continue; }   // distill-report
  const text = readFileSync(dst, "utf-8");
  if (text.includes("<!-- src:")) { console.log(`- 已有: ${name}`); continue; }   // 幂等
  const lines = text.split(/\r?\n/);
  if (lines[0]?.trim() !== "---") { console.log(`! 无 frontmatter: ${name}`); continue; }
  const end = lines.findIndex((l, i) => i > 0 && l.trim() === "---");           // frontmatter 结束行
  lines.splice(end + 1, 0, "", `<!-- src: hacker/.claude/skills/${name}/SKILL.md -->`);
  writeFileSync(dst, lines.join("\n"), "utf-8");
  console.log(`✓ ${name}`);
}
```

**⚠ 连带效应（必做）**：插入 2 行（空行+注释）使全文标题行号 **+2**——加完必须立即 `node scripts/build-knowledge.mjs` 重组 catalog，否则卡片行号全部错位 2 行。md→card 的 mtime stale 警告对本次属**预期误报**（卡片内容不含行号，无需 --force 重生成，build 补行号即可）。

**验收命令**：
```
grep -l "<!-- src: hacker/.claude/skills/" AT-src/knowledge/skills/*.md | wc -l   # =26
head -8 AT-src/knowledge/skills/privesc-linux.md                                  # 注释在 frontmatter 之后
node scripts/build-knowledge.mjs                                                  # 重组，零报错
```
**禁止**：不动 archive/；不改 frontmatter 内容本身。

---

## 4. 顺序与依赖（FD14 修订：本地 canary 取消，改真实环境实跑）

```
F-1~F-5 + F-11（A 组 = commit1，~45 行 src + ~150 行测试 + PI-prompt.md 同批同步）
  → F-8 微烟测·修前跑（15 分钟，证伪预判——Cookie 若实际在场则 F-9a 免修）
  → F-9（~55 行）+ F-10（~5 行）施工（B 组 = commit2）
  → F-8 微烟测·修后跑（回归验收：Cookie 在 / 重定向逐跳齐）
  → F-7c 加行 + build 重组（commit3）→ F-6/F-7 管线改造 + 99 篇重跑（commit4）
    ——全部施工完成 = 真实环境批的硬前置
  → 真实环境实跑（目标由操作员提供）
    前置任务：canary 剧本与通过线成稿（沿用五观察点，逐条定判据）
    观察点：worker search_knowledge 调用率与 0 命中账 / baseline 豁免质量抽样 /
            flash 模型必填参数服从率 / HAR 内容保真 / step 完成路径无干扰 /
            F-1 真机闭环（search_knowledge→Read(offset,limit)）
  → P4 开工
C 组（F-6/F-7）与 A/B 组施工及 F-8 微烟测并行不阻塞，
但必须先于真实环境批完成——实跑必须用新 catalog
```

## 5. 量级预估

| 组 | 内容 | 量级 |
|---|---|---|
| A 组 | F-1~F-5（Read 双根+行窗 / 条件渲染+寻址 / 启动即构建 / 文案×2 / planner 砍）+ F-11 PI-prompt.md 同步 | ~45 行 src + ~150 行测试 + 文档同步，半天 |
| B 组 | F-8 微烟测（修前证伪+修后回归）+ F-9 两修复 + F-10 哈希 | ~55 行 + 30 分钟验证，半天 |
| C 组 | F-6 双修 + F-7 三小件 + 重跑 99 篇 | ~40 行脚本 + 跑批几十分钟 |

## 6. 风险与预案

| # | 风险 | 预案 |
|---|---|---|
| ① | F-1 行窗口读 500KB 大文件内存压力 | 整载 ≤530KB 再切行，Node 可忽略；如介意改流式（无必要） |
| ② | F-9a extraInfo 事件乱序缓存实现错 → 头合并丢失或错配 | 单测覆盖先/后两种到达序；合并按 requestId，孤儿 extraInfo 超时丢弃 |
| ③ | F-6a 标题清单生成后深部章节 what 偏浅 | smoke 扫视确认；个别不满意可对该篇单独跑分块生成（备选方案按需启用） |
| ④ | `knowledge/` 保留前缀与 taskDir 内同名目录冲突 | 概率≈0（worker 只写 evidence/）；工具描述注明前缀保留 |
| ⑤ | 重跑 99 篇后行号全部重排 → 现有验收记录失参 | 记录本就是快照性质；重跑后按 F-7a 验收口径重新对账一次 |

## 7. 明确不做（边界）

- 知识库 per-project 复制（FD1 否决）
- planner 侧任何知识消费面（FD6 砍；将来有实证需求再议）
- HAR body 逐出调参 / dispose 竞态（观察项，canary 量级说话）
- MITM / 非 HTTP 协议捕获（维持 D4/M5 挂起）
- 离线 eval 机制 / embedding / INDEX（维持 D13/D14 砍决定，不复活）
- 本地 B 靶 S1 式 canary 复跑（FD14 取消——改真实环境实跑，目标后供）

## 8. 施工发现登记（施工会话追加；只记录不动手）

1. **F-7a 警告口径与预估偏差（已处置，无需操作员）**：施工卡预估"警告数 ≈ 13（重跑前口径）"，实跑首报 54 条。归因：卡实现按 `tier !== "exact"` 收全部模糊命中，而预估的 13 是"真错位"口径。抽查 48 条 contains 均落对行（卡片标题系统性省略原文编号前缀，如卡头"AS-REP ROASTING" vs 原文"## 2. AS-REP ROASTING"——规范化包含匹配正确，属良性非精确）；6 条 tokens 中真错位 2 条（auth-access 卡头 LLM 错拼 TECHNIQUES→TECHPRIQUES、infra-network 卡头改写编号 4→3），对这 2 篇单篇重跑后警告清零。非实现偏差，实现与卡完全一致；警告清单本身证明了 FD10 价值（修复前 13 条错位全部静默）。
2. **后台跑批工具链兼容性（环境问题，非项目问题）**：smart_bash 工具走 cmd.exe 包装，Git Bash 风格路径（`cd /d/...`）与 `tee` 管道语法均报"命令语法不正确"，99 篇重跑改用常规 bash nohup 后台解决。附带教训：清理进程严禁 `taskkill //IM node.exe`（会误杀 pi 自身进程导致会话中断）——必须用精确 PID 且先确认进程归属。
3. **跑批中断恢复路径（验证有效，供后续参考）**：--force 批量中断后，用 `git diff --name-only`（以 commit3 为基准）识别未重生成的卡，再对残留名单逐篇 `--file` 单篇补跑（0 浪费），最后 build 重组 catalog 对账。本次 7 篇补跑含 3 篇 in-flight 被杀 + 4 篇未发车。

---

---

*(本文档成稿于 2026-10-23 P4pre 竣工审查讨论；2026-10-24 决策清零（FD1-FD12）；2026-10-25 FD13（F-7c 加行落地，源路径形态经实测修订为 `<name>/SKILL.md`）+ FD14（本地 canary 取消改真实环境实跑）拍板，三项挂账下移真实环境批，F-3 preflight 加成留拍（默认不做）；同日二次细化——全部施工卡展开至文件/行/代码级（新增 §0.5 施工总规程；标出 F-7c 行号 +2 连带效应与 FindingPayload zod strip 陷阱），适配弱模型照卡施工。A/B/C 三组未动工。)*
