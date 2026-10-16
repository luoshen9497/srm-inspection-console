# SRM Inspection Console

基于 Python 与 Playwright 的多系统 API/UI 巡检控制台。支持独立调度、登录前置流程、失败重试、告警以及带截图证据的历史报告，提供中文管理界面。

本仓库为公开源码版本，配置和测试数据均为示例，不包含实际业务接口、账号凭据、服务器地址或生产报告。示例检查项、调度和通知默认关闭。

## 本地启动

需要 Python 3.11 或更新版本。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
python scripts/init_config.py
python app.py
```

访问 <http://127.0.0.1:8091/>。首次启动在终端显示随机管理员密码，管理员用户名默认为 `admin`。初始化脚本会保留已有配置；实际配置和运行数据已加入 `.gitignore`。

仅使用 API 巡检时，可暂不安装浏览器。Linux 环境需要浏览器系统依赖时可运行 `python -m playwright install --with-deps chromium`。

## 功能

- 多系统隔离：独立配置、凭据、报告、SQLite 状态与调度游标。
- API 巡检：HTTP 请求、JSON/表单请求体、业务断言、变量提取和 MeterSphere 导入。
- 登录前置流程：有序接口认证、共享 Cookie、Token 输出和 API/UI 会话交接。
- UI 场景：结构化浏览器步骤、语义定位器、登录依赖、逐步截图与失败证据。
- 调度与重试：固定间隔、每日时刻、任务互斥、漏跑处理和分阶段失败重跑。
- 通知：Webhook、钉钉签名、故障/恢复阈值、重复提醒和报告链接。
- 控制台：管理员认证、CSRF 校验、配置版本控制、审计和内置帮助中心。

在系统设置中填写自己的业务环境和巡检凭据。API 与 UI 场景分别维护；启用自动执行前应完成真实环境验收。业务检查可包含写入操作，请按实际业务权限配置。

## 配置与数据

`config/examples/` 提供三套默认停用的示例系统。初始化后，注册表写入 `config/systems.json`，各系统配置写入 `config/systems/`。配置仓储兼容旧单文件及按领域拆分的配置。

运行数据保存在 `data/`，包括管理员认证、业务凭据、报告、截图及调度状态。所有这些文件均排除在版本控制之外。UI 敏感输入使用 `${VARIABLE}` 引用，并设置 `sensitive: true`。

配置导出会脱敏凭据，但实际业务接口、请求参数和截图也可能包含业务信息，不应提交到公开仓库。

## 验证

```bash
python -m unittest discover -s tests -v
```

测试使用本地模拟接口、浏览器对象及合成数据。可选的外部 MeterSphere 验收资料没有随公开源码发布，对应测试在文件缺失时跳过。测试不会向实际业务系统发送请求。

## 部署

Docker 镜像包含 Python、Playwright 和 Chromium：

```bash
docker build -f deploy/Dockerfile -t srm-inspection:ui .
```

生产部署使用独立配置目录和数据卷，通过 HTTPS 代理访问并设置 `INSPECTION_COOKIE_SECURE=1`。管理员认证与被巡检系统的业务凭据相互独立。详细步骤和更新/回滚工具见 [部署文档](deploy/README.md)。

## 目录

```text
app.py                 HTTP 服务、巡检编排与配置管理
api_auth.py            API 登录前置流程
browser_executor.py    Playwright UI 执行器
operations.py          调度、重试、事件及通知
artifact_store.py      报告证据存储
static/                中文管理界面
config/examples/       无业务数据的示例配置
scripts/               配置初始化工具
tests/                 自动测试与合成测试数据
deploy/                Docker、systemd、Nginx 及发布工具
```
