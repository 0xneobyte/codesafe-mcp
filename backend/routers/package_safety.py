import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from config import Settings, get_settings

router = APIRouter(tags=["package-safety"])
limiter = Limiter(key_func=get_remote_address)

_popular = Path(__file__).parent.parent / "data" / "popular-packages.json"
POPULAR_PACKAGES: list[str] = json.loads(_popular.read_text())

# Packages published within this window are flagged — supply chain attacks exploit
# the gap between publish and community awareness.
TOO_NEW_HOURS = 48

Risk = Literal["safe", "warn", "suspicious", "high", "critical", "hallucinated"]

BLOCK_RISKS = {"suspicious", "high", "critical", "hallucinated"}


# ── Helpers ──────────────────────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = prev[j - 1] if ca == cb else 1 + min(prev[j - 1], prev[j], curr[j - 1])
        prev = curr
    return prev[len(b)]


def detect_typosquat(name: str) -> Optional[dict]:
    lower = name.lower()
    best: Optional[dict] = None
    for popular in POPULAR_PACKAGES:
        if popular == lower:
            return None  # exact match — it IS the popular package, not a typosquat
        dist = levenshtein(lower, popular.lower())
        if dist <= 2 and (best is None or dist < best["editDistance"]):
            best = {"similarTo": popular, "editDistance": dist}
    return best


def hours_since(iso_str: str) -> Optional[float]:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except Exception:
        return None


# ── Models ───────────────────────────────────────────────────────────────────

class PackageCheckRequest(BaseModel):
    packageName: str = Field(..., min_length=1)
    packageManager: Literal["npm", "pypi"] = "npm"


class BatchCheckRequest(BaseModel):
    packages: list[PackageCheckRequest] = Field(..., min_length=1, max_length=50)


class TyposquatMatch(BaseModel):
    similarTo: str
    editDistance: int


class PackageCheckResult(BaseModel):
    package: str
    packageManager: str
    risk: str
    exists: bool
    monthlyDownloads: Optional[int] = None
    ageInDays: Optional[float] = None
    ageInHours: Optional[float] = None
    description: Optional[str] = None
    typosquatMatch: Optional[TyposquatMatch] = None
    flags: list[str] = []
    verdict: str
    recommendation: Optional[str] = None
    blocked: bool = False


# ── Core check logic ─────────────────────────────────────────────────────────

async def _check_package(name: str, manager: str, client: httpx.AsyncClient) -> PackageCheckResult:
    typosquat = detect_typosquat(name)

    exists = False
    downloads: Optional[int] = None
    created_iso: Optional[str] = None
    description: Optional[str] = None

    if manager == "npm":
        meta_res = await client.get(f"https://registry.npmjs.org/{name}")
        if meta_res.status_code == 404:
            return PackageCheckResult(
                package=name, packageManager=manager,
                risk="hallucinated", exists=False,
                verdict=f'HALLUCINATED — "{name}" does not exist on npm. Do not install.',
                recommendation=f'Did you mean "{typosquat["similarTo"]}"?' if typosquat else "Check the package name for typos.",
                typosquatMatch=TyposquatMatch(**typosquat) if typosquat else None,
                blocked=True,
            )
        if not meta_res.is_success:
            raise HTTPException(502, f"npm registry error: {meta_res.status_code}")
        meta = meta_res.json()
        exists = True
        created_iso = meta.get("time", {}).get("created")
        description = meta.get("description")

        dl_res = await client.get(f"https://api.npmjs.org/downloads/point/last-month/{name}")
        if dl_res.is_success:
            downloads = dl_res.json().get("downloads")

    else:  # pypi
        res = await client.get(f"https://pypi.org/pypi/{name}/json")
        if res.status_code == 404:
            return PackageCheckResult(
                package=name, packageManager=manager,
                risk="hallucinated", exists=False,
                verdict=f'HALLUCINATED — "{name}" does not exist on PyPI. Do not install.',
                recommendation="Check the package name for typos.",
                typosquatMatch=TyposquatMatch(**typosquat) if typosquat else None,
                blocked=True,
            )
        if not res.is_success:
            raise HTTPException(502, f"PyPI error: {res.status_code}")
        meta = res.json()
        exists = True
        urls = meta.get("urls", [])
        created_iso = urls[0].get("upload_time") if urls else None
        description = meta.get("info", {}).get("summary")

    # ── Signal evaluation ────────────────────────────────────────────────────
    hours = hours_since(created_iso) if created_iso else None
    age_days = round(hours / 24, 1) if hours is not None else None

    risk: str = "safe"
    flags: list[str] = []

    # Typosquat
    if typosquat:
        if typosquat["editDistance"] == 1:
            risk = "critical"
            flags.append(f'Name is 1 edit away from popular package "{typosquat["similarTo"]}" — strong typosquat signal')
        else:
            risk = "high"
            flags.append(f'Name is 2 edits away from popular package "{typosquat["similarTo"]}"')

    # Age — 48-hour hard window
    if hours is not None:
        if hours < TOO_NEW_HOURS:
            if risk not in ("critical", "high"):
                risk = "suspicious"
            flags.append(f"Published only {int(hours)}h ago — within the {TOO_NEW_HOURS}h high-risk window")
        elif hours < 7 * 24:
            if risk == "safe":
                risk = "suspicious"
            flags.append(f"Package created only {int(hours / 24)} day(s) ago")
        elif hours < 30 * 24:
            if risk == "safe":
                risk = "warn"
            flags.append(f"Package is relatively new ({int(hours / 24)} days old)")

    # Downloads (npm only)
    if downloads is not None:
        if downloads < 100:
            if risk in ("safe", "warn"):
                risk = "suspicious"
            flags.append(f"Only {downloads:,} downloads last month — very low")
        elif downloads < 1000:
            if risk == "safe":
                risk = "warn"
            flags.append(f"Only {downloads:,} downloads last month")

    # Compound: < 48hr AND very low downloads
    if hours is not None and hours < TOO_NEW_HOURS and downloads is not None and downloads < 100:
        if risk not in ("critical", "high"):
            risk = "suspicious"

    # ── Verdict ──────────────────────────────────────────────────────────────
    recommendation: Optional[str] = None
    if risk == "critical":
        verdict = f'HIGH RISK — "{name}" looks like a typosquat of "{typosquat["similarTo"]}" (edit distance {typosquat["editDistance"]}). {". ".join(flags)}. Do NOT install.'
        recommendation = f'Use "{typosquat["similarTo"]}" instead'
    elif risk == "high":
        verdict = f'SUSPICIOUS — "{name}" is similar to "{typosquat["similarTo"]}" (edit distance {typosquat["editDistance"]}). {". ".join(flags)}. Verify carefully.'
        recommendation = f'Confirm you meant "{typosquat["similarTo"]}"'
    elif risk == "suspicious":
        verdict = f'SUSPICIOUS — {". ".join(flags)}. Classic supply chain attack pattern.'
        recommendation = "Verify through trusted sources before installing."
    elif risk == "warn":
        verdict = f'WARNING — {". ".join(flags)}. Proceed with caution.'
        recommendation = "Verify the package is legitimate before installing in production."
    else:
        verdict = f'Safe — well-established package{f" with {downloads:,} monthly downloads" if downloads else ""}'

    return PackageCheckResult(
        package=name,
        packageManager=manager,
        risk=risk,
        exists=exists,
        monthlyDownloads=downloads,
        ageInDays=age_days,
        ageInHours=round(hours, 1) if hours is not None else None,
        description=description,
        typosquatMatch=TyposquatMatch(**typosquat) if typosquat else None,
        flags=flags,
        verdict=verdict,
        recommendation=recommendation,
        blocked=risk in BLOCK_RISKS,
    )


# ── Routes ───────────────────────────────────────────────────────────────────

def _auth(x_api_key: str = Header(..., alias="X-Api-Key"), settings: Settings = Depends(get_settings)):
    if x_api_key != settings.BACKEND_API_KEY:
        raise HTTPException(401, "Invalid API key")


@router.post("/package/verify", response_model=PackageCheckResult)
@limiter.limit("60/minute")
async def verify_package(
    request: Request,
    body: PackageCheckRequest,
    _: None = Depends(_auth),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await _check_package(body.packageName, body.packageManager, client)


@router.post("/package/verify-batch", response_model=list[PackageCheckResult])
@limiter.limit("20/minute")
async def verify_package_batch(
    request: Request,
    body: BatchCheckRequest,
    _: None = Depends(_auth),
):
    async with httpx.AsyncClient(timeout=10.0) as client:
        results = await asyncio.gather(
            *[_check_package(p.packageName, p.packageManager, client) for p in body.packages],
            return_exceptions=True,
        )

    out: list[PackageCheckResult] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            pkg = body.packages[i]
            out.append(PackageCheckResult(
                package=pkg.packageName,
                packageManager=pkg.packageManager,
                risk="safe",
                exists=True,
                flags=[],
                verdict=f"Registry lookup failed: {r}",
                blocked=False,
            ))
        else:
            out.append(r)
    return out
