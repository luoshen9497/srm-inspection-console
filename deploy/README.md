# 部署、更新与回滚

所有主机名、配置和证书路径均为模板。请替换为自己的环境，勿将服务器密码、私钥、实际业务配置或运行数据提交到公开仓库。

## 首次安装

1. 在服务器安装 Docker、Nginx 和 Python 3，并准备受信任的 TLS 证书。
2. 本地执行 `python3 scripts/init_config.py` 创建示例配置，按业务需要修改，但保持调度和通知关闭直至验收完成。
3. 将自己的 `config/systems.json` 及关联配置放到服务器 `/etc/srm-inspection/`；创建 `/var/lib/srm-inspection/` 保存数据。这两个目录及其内容需允许容器用户 `10001:10001` 读写。
4. 构建镜像：`docker build -f deploy/Dockerfile -t srm-inspection:ui .`。
5. 安装 `deploy/srm-inspection.service` 到 `/etc/systemd/system/`，在 `/etc/srm-inspection/deployment.env` 设置 `INSPECTION_IMAGE=srm-inspection:ui` 和 `INSPECTION_COOKIE_SECURE=1`。
6. 按 `deploy/nginx-srm-inspection.conf` 配置 HTTPS 反向代理，设置实际域名、端口和证书路径。后端仅绑定 `127.0.0.1:18091`。
7. 执行 `systemctl daemon-reload` 与 `systemctl enable --now srm-inspection`。首次启动的随机管理员密码可从 `journalctl -u srm-inspection` 查看。

Nginx 模板使用 HTTPS 8091 端口；在云安全组中放行对应端口，并为证书配置续期与代理重载。不要把其他应用已经使用的入口覆盖掉。

可在 `/etc/srm-inspection/runtime.env` 设置 `INSPECTION_PUBLIC_URL=https://inspection.example.com:8091` 作为通知报告的默认入口。

## 更新现有部署

以下脚本适用于以上 Docker/systemd 目录结构与 HTTPS 8091 代理，SSH 目标需具有 root 权限，首次安装完成后才可使用。先建立并核实 SSH 主机信任：

```bash
export SRM_SSH_TARGET=root@inspection.example.com
export SRM_BASE_IMAGE=python:3.13-slim
bash deploy/update.sh
```

发布工具先运行测试，仅打包代码并记录 SHA-256，上传后校验，构建镜像并验证线上配置与 Chromium；等待正在执行的巡检结束后，备份配置和数据，再切换镜像。发布失败会自动回滚。密码通过 SSH 交互输入，不写入脚本。

当前版本目录：`/opt/srm-inspection/current`。最近备份：`/var/backups/srm-inspection/latest`。历史版本和镜像保留，按运维策略管理磁盘空间。

## 回滚

```bash
bash /opt/srm-inspection/rollback.sh /var/backups/srm-inspection/实际备份目录
```

默认恢复旧镜像与启动配置并保留最新数据。仅在紧接发布失败或明确接受恢复时间点时使用 `--restore-data`；现有数据目录会重命名保留。

## 配置与 UI 场景

旧配置迁移工具为 `migrate_config_v2.py`、`migrate_api_auth_flows.py`；先备份并使用 `--dry-run` 预览。

`deploy/sync-ui.sh` 默认只预演，支持 `--apply`、`--enable` 与 `--system`。仅在明确需要上传所选系统的 UI 账号时才使用 `--with-ui-credentials`。同步前的脱敏配置保存在服务器备份目录，实际业务凭据与报告始终不属于发布包。
