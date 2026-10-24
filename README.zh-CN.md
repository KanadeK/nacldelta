# Nacldelta

离线比较两份 AWS 网络 ACL JSON，回答一个具体问题：指定方向、TCP/UDP 端口上，哪些 IPv4/IPv6 地址真正新增放行或被禁止？计算遵循规则编号顺序和首次匹配，避免仅比较规则文本而漏掉遮蔽关系。

## 安装与体验

需要 Python 3.11+，运行时无第三方依赖，无需 AWS 凭据，不访问网络。未发布到 PyPI。源码安装会下载构建工具；离线可安装 [Release](https://github.com/KanadeK/nacldelta/releases) 的 wheel，并校验附带的 SHA256SUMS。

```sh
git clone https://github.com/KanadeK/nacldelta.git
cd nacldelta
python -m venv .venv
```

PowerShell 使用 `.venv\Scripts\Activate.ps1` 激活；macOS/Linux 使用 `source .venv/bin/activate`。

```sh
python -m pip install .
python examples/demo.py
nacldelta examples/before.json examples/after.json --protocol tcp --port 443 --format text
```

示例实际生成并检查差异：入站 TCP/443 新增禁止 `192.0.2.64/26`，共 64 个地址。最后一条命令返回 **1** 是预期行为：0 表示该查询的有效放行集合相同，1 表示改变，2 表示输入、参数或 I/O 错误。

用户自行用 AWS CLI 导出前后状态：`aws ec2 describe-network-acls --network-acl-ids acl-YOUR-ID --output json > before.json`，另行管理变更后导出 after.json。工具不会执行 AWS 命令或修改基础设施。多 ACL 导出必须用 `--before-id` / `--after-id` 各选一个。

默认输出 JSON，`--format text` 输出摘要；`--direction egress` 分析出站目的地址，默认 ingress 分析入站来源地址。每个地址族给出变更前后放行 CIDR、新增放行和新增禁止 CIDR、首个地址及十进制字符串形式的地址数量，避免 IPv6 大整数在其他 JSON 消费端被舍入。

## 边界与验证

仅分析一个目的端口、一个方向的 TCP/UDP ACL 决策。它不是完整连通性证明：不包含路由、安全组、NAT、回程流量、临时端口及 AWS 豁免流量；不分析 ICMP 或所有端口。需要完整网络模型时可使用 Batfish 等工具。

输入限 8 MiB、每份最多 256 个 ACL、所选 ACL 最多 2,000 条规则、JSON 深度 128。拒绝歧义选择、重复键、畸形规则、非规范 CIDR；地址族和方向内规则编号必须唯一。报告包含输入中的 ACL 标识和网段，应按敏感运维资料处理。工具不上传、不记录遥测，不修改输入；自行重定向的输出由用户管理。

自动测试覆盖独立逐地址判定器的交叉验证、IPv6 全空间、优先级遮蔽、协议与端口边界、异常输入和真实 CLI 流程。CI 使用三个操作系统和两个 Python 版本。具体执行记录见 [验证说明](docs/validation.md)，格式和算法见 [设计文档](docs/design.md)。

卸载：`python -m pip uninstall nacldelta`。演示临时文件自动清理；停用并删除专用虚拟环境/源码目录即可，不存在后台服务。自行保存的快照和报告需自行清理。

MIT 许可；完整参数、开发命令和安全报告入口见 [英文 README](README.md)。
