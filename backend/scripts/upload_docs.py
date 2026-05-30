#!/usr/bin/env python3
"""
Bulk upload security docs directly to Gemini File Search Store.
No backend server needed — calls Gemini API directly.

Expected folder structure:
  docs/
    nextjs/
      authentication.md
      headers.md
    supabase/
      rls.md
      auth.md

Each subfolder name = framework. Each filename (without ext) = topic.
Adds metadata: framework, topic, category=security-doc, source=official-docs.

Usage:
  python scripts/upload_docs.py --docs ./docs --store fileSearchStores/xxxx
  python scripts/upload_docs.py --docs ./docs --store fileSearchStores/xxxx --dry-run
  python scripts/upload_docs.py --docs ./docs --store fileSearchStores/xxxx --framework supabase
"""

import os
import sys
import argparse
import time
import mimetypes
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from google import genai

load_dotenv(Path(__file__).parent.parent / ".env")

ALLOWED_EXTENSIONS = {".md", ".pdf", ".txt"}


def get_owasp_hint(topic: str) -> Optional[str]:
    mapping = {
        "authentication": "A07", "auth": "A07", "session": "A07",
        "authorization": "A01", "rls": "A01", "access-control": "A01", "middleware": "A01",
        "sql-injection": "A03", "injection": "A03", "nosql": "A03", "xss": "A03",
        "secrets": "A02", "encryption": "A02", "crypto": "A02", "keys": "A02",
        "headers": "A05", "cors": "A05", "csp": "A05", "config": "A05",
        "dependencies": "A06", "packages": "A06", "cve": "A06",
        "logging": "A09", "monitoring": "A09",
        "input-validation": "A03", "validation": "A03",
        "rate-limit": "A04", "rate-limiting": "A04",
    }
    t = topic.lower().replace("_", "-")
    return mapping.get(t) or next((v for k, v in mapping.items() if k in t), None)


def build_metadata(framework: str, topic: str, source: str) -> list[dict]:
    meta = [
        {"key": "framework", "string_value": framework},
        {"key": "topic",     "string_value": topic},
        {"key": "category",  "string_value": "security-doc"},
        {"key": "source",    "string_value": source},
    ]
    owasp = get_owasp_hint(topic)
    if owasp:
        meta.append({"key": "owasp", "string_value": owasp})
    return meta


def get_already_uploaded(client: genai.Client, store_id: str) -> set[str]:
    """Return set of display_names already in the store."""
    uploaded: set[str] = set()
    try:
        page_token = None
        while True:
            cfg = {"pageSize": 20}
            if page_token:
                cfg["pageToken"] = page_token
            page = client.file_search_stores.documents.list(parent=store_id, config=cfg)
            docs = list(page)
            for doc in docs:
                name = getattr(doc, "display_name", None)
                if name:
                    uploaded.add(name)
            # check for next page
            next_token = getattr(page, "next_page_token", None)
            if not next_token:
                break
            page_token = next_token
    except Exception as e:
        print(f"  Warning: could not fetch existing docs ({e}). Will upload all files.")
    return uploaded


def scan_docs_folder(docs_dir: Path, framework_filter: Optional[str] = None) -> list[tuple[Path, str, str]]:
    entries = []
    for subfolder in sorted(docs_dir.iterdir()):
        if not subfolder.is_dir() or subfolder.name.startswith("."):
            continue
        framework = subfolder.name.lower()
        if framework_filter and framework != framework_filter.lower():
            continue
        for file in sorted(subfolder.iterdir()):
            if file.suffix.lower() not in ALLOWED_EXTENSIONS:
                continue
            topic = file.stem.lower().replace("_", "-")
            entries.append((file, framework, topic))
    return entries


def upload_file(
    client: genai.Client,
    store_id: str,
    file_path: Path,
    framework: str,
    topic: str,
    source: str,
) -> tuple[bool, str]:
    ext = file_path.suffix.lower()
    mime_type = "text/markdown" if ext == ".md" else (mimetypes.guess_type(file_path.name)[0] or "text/plain")
    metadata = build_metadata(framework, topic, source)

    try:
        operation = client.file_search_stores.upload_to_file_search_store(
            file=str(file_path),
            file_search_store_name=store_id,
            config={
                "display_name": file_path.name,
                "custom_metadata": metadata,
                "mime_type": mime_type,
            },
        )

        deadline = time.time() + 300
        while not operation.done:
            if time.time() > deadline:
                return False, "Timed out after 5 minutes"
            time.sleep(2)
            operation = client.operations.get(operation)

        return True, "OK"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="Bulk upload security docs to Gemini File Search Store")
    parser.add_argument("--docs", required=True, help="Path to docs folder (subfolders = frameworks)")
    parser.add_argument("--store", required=True, help="File Search Store ID (fileSearchStores/xxxx)")
    parser.add_argument("--source", default="official-docs", help="Source label (default: official-docs)")
    parser.add_argument("--framework", help="Upload only this framework subfolder (e.g. supabase)")
    parser.add_argument("--skip-existing", action="store_true", default=True,
                        help="Skip files already uploaded to store (default: true)")
    parser.add_argument("--no-skip-existing", dest="skip_existing", action="store_false",
                        help="Re-upload even if already in store")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be uploaded without uploading")
    args = parser.parse_args()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY not set in .env or environment")
        sys.exit(1)

    docs_dir = Path(args.docs).expanduser().resolve()
    if not docs_dir.exists():
        print(f"ERROR: docs folder not found: {docs_dir}")
        sys.exit(1)

    entries = scan_docs_folder(docs_dir, framework_filter=args.framework)
    if not entries:
        print(f"No supported files found in {docs_dir}" + (f" (framework={args.framework})" if args.framework else ""))
        sys.exit(0)

    print(f"\nCodeSafe Direct Upload")
    print(f"{'─' * 55}")
    print(f"  Docs folder : {docs_dir}")
    print(f"  Store       : {args.store}")
    print(f"  Files found : {len(entries)}")
    print(f"  Dry run     : {args.dry_run}")
    print(f"{'─' * 55}\n")

    if args.dry_run:
        frameworks: dict[str, list] = {}
        for file, fw, topic in entries:
            frameworks.setdefault(fw, []).append((file, topic))
        for fw, files in frameworks.items():
            print(f"  [{fw}] — {len(files)} file(s)")
            for f, t in files:
                owasp = get_owasp_hint(t) or "—"
                print(f"    • {f.name:<40} topic={t:<25} owasp={owasp}")
        print(f"\nDry run complete — nothing uploaded.")
        return

    client = genai.Client(api_key=api_key)

    # Fetch already-uploaded filenames to enable resume
    already_uploaded: set[str] = set()
    if args.skip_existing:
        print("  Checking store for already-uploaded files...", flush=True)
        already_uploaded = get_already_uploaded(client, args.store)
        print(f"  Found {len(already_uploaded)} existing document(s) in store.\n")

    to_upload = [
        (file, fw, topic)
        for file, fw, topic in entries
        if file.name not in already_uploaded
    ]

    skipped = len(entries) - len(to_upload)
    if skipped:
        print(f"  Skipping {skipped} already-uploaded file(s).")
    print(f"  Uploading {len(to_upload)} file(s)...\n")

    if not to_upload:
        print("Nothing to upload — all files already in store.")
        return

    ok = 0
    fail = 0
    start = time.time()

    for i, (file, framework, topic) in enumerate(to_upload, 1):
        label = f"[{i}/{len(to_upload)}] {framework}/{file.name}"
        print(f"  ↑ {label:<58}", end="", flush=True)

        success, message = upload_file(
            client=client,
            store_id=args.store,
            file_path=file,
            framework=framework,
            topic=topic,
            source=args.source,
        )

        if success:
            print("✓")
            ok += 1
        else:
            print(f"✗  {message}")
            fail += 1

    elapsed = round(time.time() - start, 1)
    print(f"\n{'─' * 55}")
    print(f"  Done in {elapsed}s — {ok} succeeded, {fail} failed")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
