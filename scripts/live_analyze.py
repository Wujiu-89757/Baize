"""通过真实 HTTP 服务上传 111.pcapng 并创建分析任务（本地免登录，供用户在页面直接查看）。"""
import json
import time
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8000"


def call(method, path, data=None, headers=None):
    h = dict(headers or {})
    body = None
    if data is not None:
        h["Content-Type"] = "application/json"
        body = json.dumps(data).encode()
    req = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def upload(path):
    boundary = "----baize" + str(time.time()).replace(".", "")
    data = Path(path).read_bytes()
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{Path(path).name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode(),
        data,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    body = b"".join(parts)
    req = urllib.request.Request(
        BASE + "/api/v1/files", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


if __name__ == "__main__":
    sample = Path(__file__).resolve().parent.parent.parent / "111.pcapng"
    f = upload(str(sample))
    print("uploaded:", f["id"], f["format"], f["sha256"][:16])
    task = call("POST", "/api/v1/analysis", {"file_id": f["id"]})
    tid = task["id"]
    print("task:", tid)
    while True:
        t = call("GET", f"/api/v1/analysis/{tid}")
        if t["status"] in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(1.5)
    print("status:", t["status"], "risk:", t["risk_level"], t["risk_score"],
          "alerts:", t["alert_count"], "packets:", t["parse_summary"].get("packets"))
    print("result page: http://127.0.0.1:8000/#/tasks/" + tid)
