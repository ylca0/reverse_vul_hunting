# Reverse Vulnerability Hunting（逆向漏洞猎杀）

基于 [opencode](https://opencode.ai) + IDA Pro 9.1（`idalib-cli`）的多智能体二进制漏洞猎杀框架。

**只挖高危。** 流水线只追求四类"皇冠"级结果——RCE、认证绕过/越权、权限提升、数据泄露——且每个确认的漏洞都附带可重放的 PoC 证据包。模型断言永远不作为证据。

方法论溯源：[Project Naptime / Big Sleep](https://googleprojectzero.blogspot.com/2024/06/project-naptime.html)（Google Project Zero）· [Project Ire](https://www.microsoft.com/en-us/research/blog/project-ire-autonomously-identifies-malware-at-scale/)（Microsoft）· [Refute-or-Promote](https://arxiv.org/abs/2604.19049)（对抗式验证）· [T3MP3ST](https://github.com/elder-plinius/T3MP3ST)（证据溯源纪律）。

> English version: [README.md](README.md)

## 为什么做这个

LLM 辅助漏洞挖掘存在"精度危机"：似是而非的误报淹没了真实漏洞。本项目用三个设计承诺来对抗它：

1. **高速** —— 工作按入口点分区，并行派发给子智能体；验证和 PoC 锻造同样并行执行。
2. **深度** —— 前置廉价 triage，把第一梯队模型的推理能力花在刀刃上：反编译审计、对抗验证、PoC 构造。
3. **要结论，不要感觉** —— 每条论断都携带证据等级；漏洞的可信度等于其工具输出的可信度。被驳回的发现保留在报告附录中，因为反驳证据同样有价值。

## 架构

```
/vulnhunt <binary>          （用户）
    │
    ▼
vuln-orchestrator           流水线规划与结果合并
    ├─► re-triage           攻击面 -> 威胁模型 + 分区图
    ├─► vuln-analyst xN     并行，每个入口点分区一个
    │                       反编译 + 模式审计 -> 漏洞 JSON
    ├─► vuln-verifier xN    并行对抗验证
    │                       （击杀授权、冷启动、实证门）
    ├─► poc-forge xN        并行 PoC 构造 -> reports/poc/<id>/
    ▼
reports/<binary>-<date>.md
```

智能体定义在 `.opencode/agent/`，知识库在 `.opencode/skill/`，流水线入口在 `.opencode/command/`。

## 命令

| 命令 | 作用 |
|---|---|
| `/vulnhunt <binary>` | 全流程：威胁模型 → 并行分区分析 → 对抗验证 → PoC 锻造 → 合并报告 |
| `/triage <binary>` | 仅攻击面 triage + 威胁模型（快速） |
| `/verify-finding <id\|JSON>` | 对单个漏洞做对抗式复核 |
| `/poc <id\|JSON>` | 为单个漏洞锻造可运行的 PoC 证据包 |

## 知识库（skills）

Skill 是领域知识沉淀的唯一位置；引用它们的智能体会自动加载。

| Skill | 内容 |
|---|---|
| `vuln-patterns` | 内存安全 + 逻辑漏洞模式目录：IDA 伪代码签名、严重度矩阵、误报陷阱 |
| `binary-threat-model` | 皇冠级影响分类、入口点分区图、函数卡片标签（`SRC_*`/`SINK_*`/`BOUNDS_*`）、加固侦察清单 |
| `vuln-provenance` | 证据阶梯（P1 工具证明 / P2 推导 / P3 模型断言）、验证阶梯（L1–L4）、击杀授权、实证门 |
| `poc-recipes` | PoC 阶梯（P0–P3）、各类漏洞触发配方、内存损坏武器化模式（用于 RCE 定级） |

## 流水线如何保证质量

- **高危门** —— 低危 bug（空指针、断言中止、纯 DoS）降级为一行"记录但不再深入"清单。报告以可利用性排序。
- **对抗验证** —— 验证者在"击杀授权"下工作，采用冷启动复核（先独立重推导，再看分析师的叙述）。一次实证测试胜过十人一致背书。
- **溯源纪律** —— 每条论断标记为 P1（工具输出）、P2（展示推导过程）或 P3（模型断言）。P3 一律降级为未验证，绝不作为漏洞呈现。CONFIRMED（动态、PoC 支撑）是最高等级。
- **覆盖诚实** —— 分析师必须声明分析了哪些分区和函数、跳过了哪些。被驳回的发现保留在附录。

## 工作区布局

```
objects/     分析目标（二进制、固件、dump）—— 原地分析，不复制
tmp/         仅中间产物（IDB 文件、崩溃 dump、测试构建）
reports/     所有文档 + PoC 证据包（reports/poc/<id>/）
```

硬性规则：绝不写入 `/tmp`、`$TMPDIR`、macOS 私有临时路径或项目外任何位置。`tmp/` 是一次性的——丢失会损害证据链的材料应放入 `reports/poc/<id>/`。

## 环境要求

- [opencode](https://opencode.ai)
- IDA Pro 9.1，`idalib-cli` 在 PATH 上（所有逆向操作经由它）
- python3、clang/gcc（PoC 构建）、jq/rg（报告组装）

## 快速开始

```sh
git clone https://github.com/ylca0/reverse_vul_hunting.git
cd reverse_vul_hunting
cp your-target-binary objects/
opencode
```

然后在 opencode 中：

```
/vulnhunt objects/your-target-binary
```

产出位于 `reports/<name>-<date>.md`，PoC 包在 `reports/poc/` 下。

## 扩展知识

- 新漏洞模式 → `.opencode/skill/vuln-patterns/SKILL.md`（每个模式一节：Hex-Rays 签名、关键问题、严重度逻辑）
- 威胁模型概念 → `binary-threat-model`
- 验证规则 → `vuln-provenance`
- PoC 技术 → `poc-recipes`

## 许可

MIT
