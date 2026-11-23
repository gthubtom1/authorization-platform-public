# 夹具用途

各子目录 active/grace/expired/revoked/blocked/not_modified/unbound 等完整信封仅供形状测试；签名 fixture-signature 是占位，时间戳不代表当前策略间隔。risk-blocked-error 是普通error加transport说明包装，不是整个HTTP响应体；transport仅为测试元数据。其他 error-only、missing-required-field、old-contract、unknown-key、signature-invalid、cross-scope 等是故意失败输入，必须按各自测试意图拒绝，不可当正常响应照抄。time-rollback 是错误示例，不是带签名授权。真实验签必须另用受控测试私钥/平台响应，不能拿占位签名证明生产接通。
