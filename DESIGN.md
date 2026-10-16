# Architecture

HTTP 控制台由 Python 标准库提供，静态界面位于 `static/`。`InspectionManager` 管理多个隔离的 `InspectionState`，共享跨系统并行限制。

`ConfigRepository` 兼容单文件与领域拆分配置，对系统设置、API 集合和 UI 集合分别进行版本控制与原子保存。管理员身份由 `AuthManager` 管理，修改类 API 校验 CSRF Token。

API 执行器支持响应断言和变量提取，`api_auth.py` 编排登录前置流程。浏览器执行器使用 Playwright，在隔离的 Chromium 上下文中执行配置化 UI 场景，并将截图交给 `ArtifactStore` 管理。

API 与 UI 是两个独立阶段，重试只重跑失败阶段。`operations.py` 负责持久化调度、事件、报告及 Webhook 投递状态；各系统的数据与凭据分别存储。

证据接口验证系统、运行、相对路径与 SHA-256。会话票据仅用于本次运行，凭据不写入报告；业务页面截图需在实际部署中按数据要求遮罩和留存。
