#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EML 文本提取工具

功能：
1. 递归扫描指定目录下的 .eml 文件
2. 自动处理普通 EML 与整体 base64 编码 EML
3. 提取邮件正文（优先 text/plain，其次 text/html）
4. 输出为 markdown 或 html
5. 输出文件命名为：来源文件夹_邮件标题（文件名安全）

示例：
    python extract_eml_text.py --input exports --output extracted_texts --format markdown
"""

from __future__ import annotations

import argparse
import base64
import html
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable


def sanitize_filename(name: str, max_len: int = 150) -> str:
    """将字符串清理为文件名安全格式。"""
    if not name:
        name = "无标题"

    name = re.sub(r"[\\/:*?\"<>|\r\n\t]+", "_", name).strip(" ._")
    name = re.sub(r"_+", "_", name)
    if not name:
        name = "无标题"

    if len(name) > max_len:
        name = name[:max_len].rstrip(" ._")

    return name


def looks_like_base64_blob(data: bytes) -> bool:
    """粗略判断文件内容是否可能是整体 base64 文本。"""
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return False

    compact = "".join(text.strip().split())
    if len(compact) < 200:
        return False

    if len(compact) % 4 != 0:
        return False

    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", compact))


def parse_eml_bytes(data: bytes):
    """解析 eml 字节内容，必要时自动进行整体 base64 解码后重试。"""
    parser = BytesParser(policy=policy.default)
    msg = parser.parsebytes(data)

    # 如果 header 很少且内容像 base64，尝试整体解码后再解析
    header_keys = list(msg.keys())
    if len(header_keys) < 2 and looks_like_base64_blob(data):
        try:
            decoded = base64.b64decode(data, validate=False)
            msg2 = parser.parsebytes(decoded)
            if len(list(msg2.keys())) >= 2:
                return msg2
        except Exception:
            pass

    return msg


def decode_part_payload(part) -> str:
    """安全解码邮件分片内容。"""
    payload = part.get_payload(decode=True)
    if payload is None:
        content = part.get_content()
        return content if isinstance(content, str) else ""

    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract_mail_body(msg) -> tuple[list[str], list[str]]:
    """提取邮件正文，返回 (plain_text_parts, html_parts)。"""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = (part.get("Content-Disposition") or "").lower()

            # 跳过附件
            if "attachment" in disposition:
                continue

            if content_type == "text/plain":
                text = decode_part_payload(part).strip()
                if text:
                    plain_parts.append(text)
            elif content_type == "text/html":
                text = decode_part_payload(part).strip()
                if text:
                    html_parts.append(text)
    else:
        content_type = msg.get_content_type()
        body = decode_part_payload(msg).strip()
        if body:
            if content_type == "text/html":
                html_parts.append(body)
            else:
                plain_parts.append(body)

    return plain_parts, html_parts


def html_to_markdown_text(html_text: str) -> str:
    """将 HTML 转为可检索文本（简化 markdown 风格）。"""
    text = html_text

    # 常见块级标签转行
    text = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", text)
    text = re.sub(r"(?i)</\s*(p|div|h[1-6]|li|tr|table)\s*>", "\n", text)

    # 链接保留文字和 URL
    text = re.sub(
        r'(?is)<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        lambda m: f"{strip_html_tags(m.group(2)).strip()} ({m.group(1).strip()})",
        text,
    )

    # 其余标签剥离
    text = strip_html_tags(text)
    text = html.unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def strip_html_tags(value: str) -> str:
    """剥离 HTML 标签。"""
    return re.sub(r"(?is)<[^>]+>", "", value)


def render_output(plain_parts: list[str], html_parts: list[str], output_format: str) -> str:
    """按指定格式生成输出文本。"""
    if output_format == "html":
        if html_parts:
            body = "\n<hr/>\n".join(html_parts)
            return f"<html><body>{body}</body></html>"

        plain_text = "\n\n".join(plain_parts).strip()
        escaped = html.escape(plain_text)
        return f"<html><body><pre>{escaped}</pre></body></html>"

    # markdown
    if plain_parts:
        return "\n\n---\n\n".join(plain_parts).strip()

    merged_html = "\n\n".join(html_parts)
    return html_to_markdown_text(merged_html)


def unique_path(path: Path) -> Path:
    """如文件已存在，自动添加序号避免覆盖。"""
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent

    idx = 2
    while True:
        candidate = parent / f"{stem}_{idx}{suffix}"
        if not candidate.exists():
            return candidate
        idx += 1


def iter_eml_files(root: Path) -> Iterable[Path]:
    """递归枚举 eml 文件。"""
    return root.rglob("*.eml")


def process_one_eml(eml_file: Path, output_dir: Path, output_format: str) -> tuple[bool, str]:
    """处理单个 eml 文件，返回 (是否成功, 结果信息)。"""
    try:
        raw = eml_file.read_bytes()
        msg = parse_eml_bytes(raw)

        subject = msg.get("Subject", "无主题")
        source_folder = eml_file.parent.name or "未知来源"

        safe_subject = sanitize_filename(subject)
        safe_folder = sanitize_filename(source_folder)

        plain_parts, html_parts = extract_mail_body(msg)
        content = render_output(plain_parts, html_parts, output_format)

        if not content.strip():
            content = "[空正文]"

        ext = ".md" if output_format == "markdown" else ".html"
        output_name = f"{safe_folder}_{safe_subject}{ext}"
        output_path = unique_path(output_dir / output_name)

        output_path.write_text(content, encoding="utf-8")
        return True, str(output_path)
    except Exception as exc:
        return False, f"{eml_file} -> {exc}"


def main():
    parser = argparse.ArgumentParser(description="提取 EML 邮件正文为可检索文本")
    parser.add_argument("--input", default="exports", help="EML 根目录（默认: exports）")
    parser.add_argument("--output", default="extracted_texts", help="输出目录（默认: extracted_texts）")
    parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="输出格式（默认: markdown）",
    )

    args = parser.parse_args()

    input_root = Path(args.input).resolve()
    output_root = Path(args.output).resolve()

    if not input_root.exists() or not input_root.is_dir():
        print(f"❌ 输入目录不存在或不是目录: {input_root}")
        raise SystemExit(1)

    output_root.mkdir(parents=True, exist_ok=True)

    eml_files = list(iter_eml_files(input_root))
    if not eml_files:
        print(f"⚠️ 在 {input_root} 未找到 .eml 文件")
        return

    print(f"📂 输入目录: {input_root}")
    print(f"📝 输出目录: {output_root}")
    print(f"🔧 输出格式: {args.format}")
    print(f"📧 发现 EML 文件: {len(eml_files)}")

    success_count = 0
    failed: list[str] = []

    for eml in eml_files:
        ok, info = process_one_eml(eml, output_root, args.format)
        if ok:
            success_count += 1
        else:
            failed.append(info)

    print("\n================ 处理完成 ================")
    print(f"✅ 成功: {success_count}")
    print(f"❌ 失败: {len(failed)}")

    if failed:
        print("\n失败详情（前20条）：")
        for item in failed[:20]:
            print(f" - {item}")


if __name__ == "__main__":
    main()
