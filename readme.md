# Github-Dify-Sync

这是一个用于在 Github 仓库与 Dify AI 知识库之间保持文档同步的工具。支持通过 Github Webhook 自动同步更新,也可以手动触发同步。

## 功能特点

- 支持多个仓库/目录与 Dify 知识库的映射
- 自动同步 Github 代码仓库的文件更新到 Dify 知识库
- 支持 Github Webhook 实时同步
- 提供手动触发同步的接口
- 支持错误通知(Email + Webhook)，尚未测试该功能

## 配置说明

复制 `config.example.yaml` 为 `config.yaml` 并按需修改各项配置:

```yaml
database:
  # MySQL数据库配置
  host: localhost 
  port: 3306
  user: root
  password: password
  database: dify_sync

github:
  pat: "your-github-pat-token"  # Github Personal Access Token

dify:
  api_key: "your-api-key"   # Dify API Key
  base_url: "https://api.dify.ai/v1"

notifications:  # 错误通知配置(可选)
  smtp:
    enabled: true
    # ... 邮件配置

mapping:  # 仓库映射配置
  - name: "docs-repo"   # 映射名称,用于手动webhook
    github:
      owner: "owner"   # Github用户名/组织名
      repo: "repo"     # 仓库名
      branch: "main"   # 分支
      path: "docs"     # 需要同步的目录(可选)
      webhook_path: "/github/docs-repo"  # Github Webhook路径
      webhook_secret: "secret"     # Github Webhook Secret
    dify:
      dateset_id: "dataset-id"   # Dify数据集ID

manual_webhook:  
  auth_token: "your-token"  # 手动触发webhook的token
```

## Github Webhook 配置使用

1. 在 Github 仓库设置中添加 Webhook:
   - Payload URL: `https://your-domain.com/github/docs-repo` (与配置文件中的webhook_path对应)，注意main.py默认监听的是localhost
   - Content type: application/json
   - Secret: 设置webhook secret (与配置文件中的webhook_secret对应)
   - 选择 "Just the push event"

2. 完成配置后,每次向该仓库推送代码,都会自动触发同步

## 手动触发同步

可以通过以下API手动触发同步:

```bash
curl -X POST "http://localhost:8000/manual_webhook?auth_token=your-token" \
     -H "Content-Type: application/json" \
     -d '{"mapping_name": "docs-repo"}'
```

参数说明:
- auth_token: 配置文件中设置的manual_webhook.auth_token
- mapping_name: 配置文件中mapping下的name

## 部署运行

1. 安装依赖:
```bash
pip install -r requirements.txt
```

2. 初始化数据库:
```bash
mysql -u root -p
create database dify_sync;
```

3. 修改配置文件:
```bash
cp config.example.yaml config.yaml
vi config.yaml  # 按实际情况修改配置
```

4. 运行程序:
```bash
python main.py
```

建议使用 systemd 等工具确保程序持续运行。

## 常见问题

1. Github Webhook 测试失败
- 检查 webhook_secret 是否配置正确
- 确认反向代理是否正确配置，Github Webhook 需要能够访问到程序
- 查看程序日志是否有报错信息

2. 同步失败
- 检查 Github PAT token 权限是否足够
- 确认 Dify API key 是否正确
- 查看 notifications 配置的错误通知

## TODO

1. 测试错误通知功能
2. 文件类型预处理或筛选
