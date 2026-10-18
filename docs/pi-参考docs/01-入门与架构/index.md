# Pi

Pi is an extensible AI agent that works from your terminal. Give it a goal and a working folder, and it can inspect files, run commands, edit content, and work through multi-step tasks.

Use Pi for software development, research notes, writing projects, data files, or hobby work. You can use Pi as is, prompt it to adapt itself to your workflow, or build other applications powered by Pi using the SDK.

## Start using Pi

New to Pi? Follow the [Quickstart](quickstart.md) to install Pi, connect a model, and complete your first task.

If Pi is already installed, choose what you want to do:

- [Use Pi interactively](../02-运行与环境指南/usage.md) to add files, run commands, direct ongoing work, and export results.
- [Choose a model](../02-运行与环境指南/models.md) or connect a subscription, API key, local model, or compatible endpoint.
- [Continue or branch a session](../02-运行与环境指南/sessions.md) to resume work or explore another approach without losing history.
- [Configure Pi](../03-定制与配置指南/configuration.md) for your preferences, working folders, instructions, and reusable resources.
- [Understand how Pi works](how-pi-works.md), including tools, context, sessions, and the agent loop.

## Customize Pi

Pi can reuse prompts, load specialized instructions, add executable integrations, change its terminal interface, connect model services, and distribute these resources as packages.
Use the [Quickstart customization chooser](quickstart.md#choose-how-to-customize-pi) to select the smallest mechanism that meets your need.

## Automate or embed Pi

- Use [print mode](../05-参考手册与底层规范/cli.md#invocation-and-output) for one-off and scripted tasks.
- Use [JSON event stream mode](../05-参考手册与底层规范/json.md) to consume structured events from one run.
- Use [RPC mode](../05-参考手册与底层规范/rpc.md) to control a separate Pi process.
- Use the [TypeScript SDK](../04-二次开发与集成/sdk.md) to run Pi inside an application.

## Find reference and setup information

Use the reference pages to look up [CLI options](../05-参考手册与底层规范/cli.md), [settings](../05-参考手册与底层规范/settings.md), [providers](../05-参考手册与底层规范/providers.md), [keybindings](../05-参考手册与底层规范/keybindings.md), and [environment variables](../05-参考手册与底层规范/environment-variables.md).

For platform-specific help, see [Terminal Setup](../02-运行与环境指南/terminal-setup.md), [Windows](../02-运行与环境指南/windows.md), [tmux](../02-运行与环境指南/tmux.md), [Termux on Android](../02-运行与环境指南/termux.md), or [Containerization](../02-运行与环境指南/containerization.md).

## Work safely

Pi's tools and extensions run with the permissions of the Pi process. Project trust controls which project resources Pi loads, but it does not sandbox tool calls. Review [Security](../02-运行与环境指南/security.md) before using untrusted files, repositories, extensions, or unattended automation.
