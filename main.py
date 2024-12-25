import os
import sys
import yaml
import hmac
import hashlib
import requests
import traceback
import smtplib
import json
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime

from flask import Flask, request, jsonify, abort
import pymysql

#############################################
# 1. 读取配置文件
#############################################
CONFIG_FILE = 'config.yaml'
if not os.path.exists(CONFIG_FILE):
    print(f"未找到配置文件: {CONFIG_FILE}")
    sys.exit(1)

with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)


#############################################
# 2. 数据库初始化
#############################################
db_config = config.get('database', {})
try:
    connection = pymysql.connect(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 3306),
        user=db_config.get('user', 'root'),
        password=db_config.get('password', ''),
        database=db_config.get('database', ''),
        charset='utf8mb4'
    )
except Exception as e:
    print("数据库连接失败，请检查数据库配置")
    print(e)
    sys.exit(1)

# 建立一张表，用于记录文件与 Dify Document 之间的对应关系
# 根据需要可增减字段，这里仅列出最常用信息
TABLE_INIT_SQL = """
CREATE TABLE IF NOT EXISTS github_dify_sync (
    id INT AUTO_INCREMENT PRIMARY KEY,
    repo_name VARCHAR(255) NOT NULL,
    branch VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    commit_hash VARCHAR(40) NOT NULL,
    dify_document_id VARCHAR(255),
    dataset_id VARCHAR(255),
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)
"""
with connection.cursor() as cursor:
    cursor.execute(TABLE_INIT_SQL)
connection.commit()

#############################################
# 3. 初始化 Flask
#############################################
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

#############################################
# 4. 发送错误通知的辅助函数
#############################################
def send_error_notifications(subject, content):
    """
    发送错误通知（Email + 自定义Webhook），若在config中启用。
    """
    # 发送邮件
    smtp_conf = config.get('notifications', {}).get('smtp', {})
    if smtp_conf.get('enabled'):
        try:
            msg = MIMEText(content, 'plain', 'utf-8')
            msg['Subject'] = Header(subject, 'utf-8')
            msg['From'] = smtp_conf.get('username')
            msg['To'] = ",".join(smtp_conf.get('recipients', []))

            server = smtplib.SMTP(smtp_conf.get('host'), smtp_conf.get('port'))
            server.starttls()
            server.login(smtp_conf.get('username'), smtp_conf.get('password'))
            server.sendmail(smtp_conf.get('username'),
                            smtp_conf.get('recipients', []),
                            msg.as_string())
            server.quit()
        except Exception as e:
            print("发送邮件失败：", e)

    # 发送Webhook
    webhook_conf = config.get('notifications', {}).get('webhook', {})
    if webhook_conf.get('enabled'):
        url = webhook_conf.get('url')
        method = webhook_conf.get('method', 'GET').upper()
        try:
            if method == 'GET':
                requests.get(url, params={'subject': subject, 'content': content}, timeout=10)
            else:
                requests.post(url, json={'subject': subject, 'content': content}, timeout=10)
        except Exception as e:
            print("发送Webhook失败：", e)


#############################################
# 5. GitHub 相关函数
#############################################
def get_github_file_content(owner, repo, branch, path, github_pat):
    """
    通过 GitHub API 获取某个文件的内容（Base64 编码），并解码返回 bytes。
    """
    headers = {
        'Authorization': f'Bearer {github_pat}',
        'X-GitHub-Api-Version': '2022-11-28',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        if 'content' in data and data['content']:
            import base64
            file_content = base64.b64decode(data['content'])
            return file_content
        else:
            return None
    else:
        return None

def list_github_files_recursive(owner, repo, branch, path, github_pat):
    """
    递归列出 GitHub 仓库指定路径下的所有文件（返回文件的相对路径列表）。
    """
    headers = {
        'Authorization': f'Bearer {github_pat}',
        'X-GitHub-Api-Version': '2022-11-28',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}'
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return []
    items = r.json()
    if not isinstance(items, list):
        return []
    files = []
    for item in items:
        if item['type'] == 'file':
            files.append(item['path'])
        elif item['type'] == 'dir':
            files.extend(list_github_files_recursive(owner, repo, branch, item['path'], github_pat))
    return files

def get_latest_commit_hash(owner, repo, branch, path, github_pat):
    """
    获取该文件在 GitHub 上最新的 commit hash（用于判断是否更新）。
    可以通过调用 repos/{owner}/{repo}/commits?path=...&sha=branch 获取最近一次提交信息。
    """
    headers = {
        'Authorization': f'Bearer {github_pat}',
        'X-GitHub-Api-Version': '2022-11-28',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{owner}/{repo}/commits?path={path}&sha={branch}&per_page=1'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        commits = r.json()
        if commits and len(commits) > 0:
            return commits[0].get('sha', '')[:40]
    return ''


#############################################
# 6. Dify 同步相关函数
#############################################
def list_dify_documents(dataset_id, dify_api_key, base_url):
    """
    获取知识库中现有文档列表（以方便查找对应文件是否已存在）。
    注意：返回的数据量大时需要分页，这里为简化仅取第一页
    """
    url = f"{base_url}/datasets/{dataset_id}/documents"
    headers = {
        'Authorization': f'Bearer {dify_api_key}'
    }
    params = {'page': 1, 'limit': 200}  # 这里限制200，可根据需要修改或循环翻页
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 200:
        return resp.json().get('data', [])
    else:
        return []

def create_dify_document(dataset_id, file_path, file_content, dify_config):
    """
    向 Dify 知识库中上传文件，返回文档 ID 或抛出异常。
    """
    base_url = dify_config['base_url']
    api_key = dify_config['api_key']
    indexing_technique = dify_config['indexing_technique']
    process_rule = dify_config['process_rule']

    url = f"{base_url}/datasets/{dataset_id}/document/create_by_file"
    headers = {
        'Authorization': f'Bearer {api_key}'
    }

    import tempfile
    # 使用 with 语句确保文件被正确关闭
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_content)
        tmp.flush()
        tmp_name = tmp.name

        data_json = {
            'indexing_technique': indexing_technique,
            'process_rule': process_rule
        }

        # 使用另一个 with 语句确保文件正确打开和关闭
        with open(tmp_name, 'rb') as f:
            files = {
                'data': (None, json.dumps(data_json), 'text/plain'),
                'file': (file_path, f, 'application/octet-stream'),
            }
            resp = requests.post(url, headers=headers, files=files)

    # 最后删除临时文件
    try:
        os.unlink(tmp_name)
    except:
        pass

    if resp.status_code == 200:
        return resp.json()['document']['id']
    else:
        raise Exception(f"创建Dify文档失败: {resp.text}")

def update_dify_document(dataset_id, document_id, file_path, file_content, dify_config):
    """
    更新已存在的 Dify 文档，返回文档 ID 或抛出异常。
    """
    base_url = dify_config['base_url']
    api_key = dify_config['api_key']
    indexing_technique = dify_config['indexing_technique']
    process_rule = dify_config['process_rule']

    url = f"{base_url}/datasets/{dataset_id}/documents/{document_id}/update_by_file"
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    data_json = {
        'name': file_path,
        'indexing_technique': indexing_technique,
        'process_rule': process_rule
    }

    import tempfile
    # 使用 with 语句确保文件被正确关闭
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_content)
        tmp.flush()
        tmp_name = tmp.name

        # 使用另一个 with 语句确保文件正确打开和关闭
        with open(tmp_name, 'rb') as f:
            files = {
                'data': (None, json.dumps(data_json), 'text/plain'),
                'file': (file_path, f, 'application/octet-stream'),
            }
            resp = requests.post(url, headers=headers, files=files)

    # 最后删除临时文件
    try:
        os.unlink(tmp_name)
    except:
        pass

    if resp.status_code == 200:
        return resp.json()['document']['id']
    else:
        raise Exception(f"更新Dify文档失败: {resp.text}")


def delete_dify_document(dataset_id, document_id, dify_config):
    """
    删除指定的 Dify 文档
    """
    base_url = dify_config['base_url']
    api_key = dify_config['api_key']

    url = f"{base_url}/datasets/{dataset_id}/documents/{document_id}"
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    resp = requests.delete(url, headers=headers)
    if resp.status_code != 200:
        raise Exception(f"删除Dify文档失败: {resp.text}")


#############################################
# 7. 同步逻辑相关函数
#############################################

def get_db_record(repo_name, branch, file_path, dataset_id):
    """
    从数据库获取某文件对应的记录,返回字典格式
    """
    with connection.cursor() as cursor:
        sql = """SELECT id, commit_hash, dify_document_id
                 FROM github_dify_sync
                 WHERE repo_name=%s AND branch=%s AND file_path=%s AND dataset_id=%s
                 LIMIT 1"""
        cursor.execute(sql, (repo_name, branch, file_path, dataset_id))
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'commit_hash': row[1], 
                'dify_document_id': row[2]
            }
        return None


def add_db_record(repo_name, branch, file_path, commit_hash, dify_document_id, dataset_id):
    """
    新增数据库记录
    """
    with connection.cursor() as cursor:
        sql = """INSERT INTO github_dify_sync(repo_name, branch, file_path, commit_hash, dify_document_id, dataset_id)
                 VALUES(%s, %s, %s, %s, %s, %s)"""
        cursor.execute(sql, (repo_name, branch, file_path, commit_hash, dify_document_id, dataset_id))
    connection.commit()


def update_db_record(id_, commit_hash, dify_document_id):
    """
    更新数据库记录
    """
    with connection.cursor() as cursor:
        sql = """UPDATE github_dify_sync
                 SET commit_hash=%s, dify_document_id=%s
                 WHERE id=%s"""
        cursor.execute(sql, (commit_hash, dify_document_id, id_))
    connection.commit()


def delete_db_record(id_):
    """
    删除数据库记录
    """
    with connection.cursor() as cursor:
        sql = "DELETE FROM github_dify_sync WHERE id=%s"
        cursor.execute(sql, (id_,))
    connection.commit()


def full_sync_for_mapping(mapping_cfg):
    """
    对该映射做一次完整同步,以GitHub文件列表为主,Dify知识库为辅进行校验
    """
    github_pat = config['github']['pat']
    owner = mapping_cfg['github']['owner']
    repo = mapping_cfg['github']['repo']
    branch = mapping_cfg['github']['branch']
    path = mapping_cfg['github'].get('path', '')
    dataset_id = mapping_cfg['dify']['dateset_id']

    dify_config = {
        'api_key': config['dify']['api_key'],
        'base_url': config['dify']['base_url'],
        'indexing_technique': mapping_cfg['dify'].get('indexing_technique', 'high_quality'),
        'process_rule': mapping_cfg['dify'].get('process_rule', {"mode": "automatic"})
    }

    # 1. 获取GitHub上的所有文件
    github_files = list_github_files_recursive(owner, repo, branch, path, github_pat)
    
    # 2. 获取数据库中的记录
    db_records = {}
    with connection.cursor() as cursor:
        sql = """SELECT id, file_path, commit_hash, dify_document_id
                 FROM github_dify_sync
                 WHERE repo_name=%s AND branch=%s AND dataset_id=%s"""
        cursor.execute(sql, (repo, branch, dataset_id))
        for row in cursor.fetchall():
            record_id, file_path, commit_hash, doc_id = row
            db_records[file_path] = {
                'id': record_id,
                'commit_hash': commit_hash,
                'doc_id': doc_id
            }

    # 3. 获取Dify知识库中的文档
    dify_docs = {}
    for doc in list_dify_documents(dataset_id, dify_config['api_key'], dify_config['base_url']):
        doc_name = doc.get('name', '')
        if doc_name:
            dify_docs[doc_name] = doc['id']

    # 4. 处理需要删除的文档(在Dify中存在但GitHub上已不存在)
    for file_path, doc_id in dify_docs.items():
        if file_path not in github_files:
            try:
                delete_dify_document(dataset_id, doc_id, dify_config)
                # 如果数据库中有记录也删除
                if file_path in db_records:
                    delete_db_record(db_records[file_path]['id'])
                print(f"[删除文件] {file_path} 已从Dify删除")
            except Exception as e:
                print(f"[删除文件] 失败: {file_path}, {str(e)}")
                send_error_notifications("删除文件失败", f"文件: {file_path}\n错误: {str(e)}")

    # 5. 处理GitHub上的文件(新增或更新)
    for file_path in github_files:
        latest_hash = get_latest_commit_hash(owner, repo, branch, file_path, github_pat)
        file_content = get_github_file_content(owner, repo, branch, file_path, github_pat)
        if file_content is None:
            continue

        db_record = db_records.get(file_path)
        dify_doc_id = dify_docs.get(file_path)

        try:
            if dify_doc_id:
                # 文档在Dify中存在,检查是否需要更新
                if not db_record or db_record['commit_hash'] != latest_hash:
                    doc_id = update_dify_document(dataset_id, dify_doc_id, file_path, file_content, dify_config)
                    if db_record:
                        update_db_record(db_record['id'], latest_hash, doc_id)
                    else:
                        add_db_record(repo, branch, file_path, latest_hash, doc_id, dataset_id)
                    print(f"[更新文件] {file_path}")
            else:
                # 文档在Dify中不存在,需要新增
                doc_id = create_dify_document(dataset_id, file_path, file_content, dify_config)
                if db_record:
                    update_db_record(db_record['id'], latest_hash, doc_id)
                else:
                    add_db_record(repo, branch, file_path, latest_hash, doc_id, dataset_id)
                print(f"[新增文件] {file_path}")
                
        except Exception as e:
            print(f"[处理文件] 失败: {file_path}, {str(e)}")
            send_error_notifications("处理文件失败", f"文件: {file_path}\n错误: {str(e)}")


#############################################
# 8. Flask 路由定义
#############################################

# 8.1 GitHub Webhook
@app.route('/<path:webhook_route>', methods=['POST'])
def github_webhook_handler(webhook_route):
    """
    根据 mapping 配置里的 webhook_path 判断走到此函数。
    用于处理 GitHub push 事件。
    """
    # 先找到对应 mapping
    target_mapping = None
    for m in config.get('mapping', []):
        if m['github'].get('webhook_path') and m['github']['webhook_path'].strip('/') == webhook_route.strip('/'):
            target_mapping = m
            break
    if not target_mapping:
        abort(404, description="No matching webhook mapping")

    # 验证 secret
    secret = target_mapping['github'].get('webhook_secret', '')
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature or not secret:
        abort(403, description="Missing signature or secret.")
    sha_name, signature_value = signature.split('=')
    if sha_name != 'sha256':
        abort(403, description="Only sha256 is supported.")
    mac = hmac.new(secret.encode('utf-8'), msg=request.data, digestmod='sha256')
    if not hmac.compare_digest(str(mac.hexdigest()), str(signature_value)):
        abort(403, description="Signature mismatch.")

    # 解析事件类型
    event = request.headers.get('X-GitHub-Event')
    if event != 'push':
        # 本示例只处理 push
        return jsonify({"msg": "Not a push event"}), 200

    payload = request.json
    # 解析 push 中的 commits，看看哪些文件新增、修改、删除
    # 结构参考 GitHub push event 的 payload
    commits = payload.get('commits', [])
    repo_name = payload.get('repository', {}).get('name')
    branch_ref = payload.get('ref', '')  # eg: refs/heads/main
    branch = branch_ref.replace('refs/heads/', '')

    # 只在映射的 branch 相同才继续处理(如有需要)
    if branch != target_mapping['github']['branch']:
        return jsonify({"msg": "Branch not match, skip"}), 200

    github_pat = config['github']['pat']
    dataset_id = target_mapping['dify']['dateset_id']
    dify_config = {
        'api_key': config['dify']['api_key'],
        'base_url': config['dify']['base_url'],
        'indexing_technique': target_mapping['dify'].get('indexing_technique', 'high_quality'),
        'process_rule': target_mapping['dify'].get('process_rule', {"mode": "automatic"})
    }

    for commit in commits:
        added = commit.get('added', [])
        modified = commit.get('modified', [])
        removed = commit.get('removed', [])
        for file_path in added + modified:
            # 如果 mapping 中指定了 path 限制，需要判断是否在该目录下
            if 'path' in target_mapping['github']:
                sync_dir = target_mapping['github']['path'].strip('/')
                if not file_path.startswith(sync_dir):
                    continue

            # 计算最新 commit hash
            latest_hash = get_latest_commit_hash(target_mapping['github']['owner'], repo_name, branch, file_path, github_pat)
            file_content = get_github_file_content(target_mapping['github']['owner'], repo_name, branch, file_path, github_pat)
            if file_content is None:
                continue

            # 查询数据库中是否有记录
            record = get_db_record(repo_name, branch, file_path, dataset_id)
            if record:
                # 更新
                if record['commit_hash'] != latest_hash:
                    try:
                        updated_doc_id = update_dify_document(dataset_id, record['dify_document_id'], file_path, file_content, dify_config)
                        update_db_record(record['id'], latest_hash, updated_doc_id)
                        print(f"[Webhook更新文件] {file_path}")
                    except Exception as e:
                        print(f"更新文件失败: {file_path}, {str(e)}")
                        send_error_notifications("更新文件失败", f"文件: {file_path}\n错误: {traceback.format_exc()}")
            else:
                # 新增
                try:
                    doc_id = create_dify_document(dataset_id, file_path, file_content, dify_config)
                    add_db_record(repo_name, branch, file_path, latest_hash, doc_id, dataset_id)
                    print(f"[Webhook新增文件] {file_path}")
                except Exception as e:
                    print(f"新增文件失败: {file_path}, {str(e)}")
                    send_error_notifications("新增文件失败", f"文件: {file_path}\n错误: {traceback.format_exc()}")

        for file_path in removed:
            # 同样判断是否在 path 下
            if 'path' in target_mapping['github']:
                sync_dir = target_mapping['github']['path'].strip('/')
                if not file_path.startswith(sync_dir):
                    continue

            record = get_db_record(repo_name, branch, file_path, dataset_id)
            if record:
                try:
                    if record['dify_document_id']:
                        delete_dify_document(dataset_id, record['dify_document_id'], dify_config)
                    delete_db_record(record['id'])
                    print(f"[Webhook删除文件] {file_path}")
                except Exception as e:
                    print(f"删除文件失败: {file_path}, {str(e)}")
                    send_error_notifications("删除文件失败", f"文件: {file_path}\n错误: {traceback.format_exc()}")

    return jsonify({"msg": "Push event processed"}), 200


# 8.2 用户手动触发WebHook
@app.route('/manual_webhook', methods=['POST'])
def manual_webhook():
    """
    手动触发同步，通过配置文件中的 auth_token 进行鉴权。
    POST /manual_webhook?auth_token=your-auth-token
    body: 
    {
       "mapping_name": "docs-repo"  # 要同步的mapping
    }
    """
    auth_token = request.args.get('auth_token', '')
    if auth_token != config.get('manual_webhook', {}).get('auth_token', ''):
        abort(403, description="Invalid auth token.")

    req_data = request.json if request.is_json else {}
    mapping_name = req_data.get('mapping_name')
    if not mapping_name:
        return jsonify({"msg": "mapping_name missing"}), 400

    # 找到相应配置
    target_mapping = None
    for m in config.get('mapping', []):
        if m.get('name') == mapping_name:
            target_mapping = m
            break
    if not target_mapping:
        return jsonify({"msg": f"No mapping found for {mapping_name}"}), 404

    try:
        full_sync_for_mapping(target_mapping)
    except Exception as e:
        print(f"手动同步失败: {str(e)}")
        send_error_notifications("手动同步失败", f"Mapping: {mapping_name}\n错误: {traceback.format_exc()}")

    return jsonify({"msg": f"Sync for {mapping_name} triggered"}), 200


#############################################
# 9. 启动时的初始化全量同步（可选）
#############################################
def startup_full_sync():
    """
    工具启动时，对所有mapping进行一次完整同步。
    """
    for m in config.get('mapping', []):
        try:
            print(f"开始全量同步: {m['name']}")
            full_sync_for_mapping(m)
            print(f"同步完成: {m['name']}\n")
        except Exception as e:
            print(f"同步失败: {m['name']}, error={str(e)}")
            send_error_notifications("启动同步失败", f"Mapping: {m['name']}\n错误: {traceback.format_exc()}")


#############################################
# 主入口
#############################################
if __name__ == '__main__':
    # 可选：启动时做一次全量同步
    startup_full_sync()

    # 启动 Flask 监听
    # port = int(os.environ.get("PORT", 8000))
    app.run(host='127.0.0.1', port=8000, debug=True)