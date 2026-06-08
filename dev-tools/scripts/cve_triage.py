#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Automated CVE triage for Apache Solr Docker images.

Scans a Solr Docker image using Docker Scout, filters to application-level
CRITICAL/HIGH CVEs, cross-references against Solr's published VEX file and
open solr-site PRs, and optionally uses an agentic LLM to analyze whether
each CVE is exploitable in Solr. Can output results to console, write VEX
markdown files, or create PRs on solr-site.

Usage examples:

  # List unresolved CVEs (no LLM, no PRs):
  python3 cve_triage.py --solr-version 10.0.0 --dry-run

  # Analyze with LLM and write VEX files locally:
  export ANTHROPIC_API_KEY=sk-...
  python3 cve_triage.py --solr-version 10.0.0 --output-dir ./vex-output/

  # Full run: analyze and create PRs on solr-site:
  export ANTHROPIC_API_KEY=sk-... SOLRBOT_GITHUB_TOKEN=ghp_...
  python3 cve_triage.py --solr-version 10.0.0 --reviewers "user1,user2"

Prerequisites:
  - Docker with Docker Scout CLI plugin installed
  - pip install -r cve_triage_requirements.txt
  - For PR creation: SOLRBOT_GITHUB_TOKEN env var
  - For LLM analysis: ANTHROPIC_API_KEY env var
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import textwrap
import time
from datetime import date

# ---------------------------------------------------------------------------
# Lazy imports with helpful error messages
# ---------------------------------------------------------------------------

def _try_import(module_name):
    """Import a module, return None if missing."""
    try:
        return __import__(module_name)
    except ImportError:
        return None


yaml = _try_import("yaml")
requests = _try_import("requests")
anthropic = _try_import("anthropic")


def _check_imports(need_llm=False, need_github=False):
    """Check that required modules are available; exit with install hint if not."""
    missing = []
    if not yaml:
        missing.append("PyYAML")
    if not requests:
        missing.append("requests")
    if need_llm and not anthropic:
        missing.append("anthropic")
    if need_github:
        try:
            from github import Github  # noqa: F401
        except ImportError:
            missing.append("PyGithub")
    if missing:
        print(
            f"ERROR: Missing required Python modules: {', '.join(missing)}\n"
            f"Please run:\n"
            f"  pip install -r dev-tools/scripts/requirements.txt\n"
            f"  pip install -r dev-tools/scripts/cve_triage_requirements.txt",
            file=sys.stderr,
        )
        sys.exit(1)

log = logging.getLogger("cve_triage")

MODEL_ALIASES = {
    "best": "claude-opus-4-8",
    "balanced": "claude-sonnet-4-6",
    "fast": "claude-haiku-4-5-20251001",
}

# Pricing per million tokens (USD) as of June 2026
MODEL_PRICING = {
    "claude-opus-4-8":           {"input": 5.0,  "output": 25.0},
    "claude-opus-4-7":           {"input": 5.0,  "output": 25.0},
    "claude-opus-4-6":           {"input": 5.0,  "output": 25.0},
    "claude-sonnet-4-6":         {"input": 3.0,  "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 1.0,  "output": 5.0},
}


def estimate_cost(model, input_tokens, output_tokens):
    """Estimate USD cost for a given model and token counts."""
    pricing = MODEL_PRICING.get(model)
    if not pricing:
        return None
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000

# ---------------------------------------------------------------------------
# Prompt template for LLM CVE analysis
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a security analyst triaging CVEs for Apache Solr.

    You will be given details about a CVE affecting a Java dependency that ships
    with a specific Solr Docker image. Your job is to determine whether the
    vulnerability is actually exploitable in the context of Apache Solr.

    IMPORTANT context about your tools and data:
    - The DEPENDENCY VERSION reported by Docker Scout (in the CVE details) is
      AUTHORITATIVE — it reflects what actually ships in the Docker image.
    - Your source code search tools operate on a LOCAL GIT CHECKOUT of Solr.
      This checkout may be on a different branch (e.g. main) than what was used
      to build the Docker image. Do NOT use the source tree to determine
      dependency versions — use it only to understand CODE PATHS and how Solr
      uses the library.
    - You will be given pre-gathered version information showing the dependency
      version on relevant branches. Use this to reason about whether fixes are
      already in progress.

    Use your tools to:
    1. Check if Solr imports or uses the affected library classes/methods.
    2. Determine if the vulnerable code path is reachable at runtime.
    3. Consider whether exploitation requires special configuration that Solr
       does not enable by default.
    4. Check if the dependency is only used in tests or build tooling.

    IMPORTANT: Be efficient. Do not aim for a perfect analysis — aim for a
    confident-enough assessment. A few targeted searches are usually sufficient:
    - One grep for imports/usage of the affected package
    - One or two file reads to understand the usage context
    - Then conclude.
    Do NOT exhaustively search every module or read entire files when a few key
    lines give you the answer. If after 3-5 tool calls you have a reasonable
    picture, provide your conclusion. Use "in_triage" if genuinely uncertain
    rather than doing more research.

    After your analysis, respond with ONLY a JSON object (no markdown fences):
    {
      "state": "not_affected" | "affected" | "in_triage",
      "justification": "<ONLY for not_affected — one of: component_not_present, vulnerable_code_not_reachable, vulnerable_code_cannot_be_controlled_by_adversary, requires_configuration, requires_dependency, requires_environment, protected_by_mitigating_control. OMIT this field when state is affected or in_triage>",
      "reasoning": "<markdown-formatted analysis using the structure below>",
      "affected_jars": ["<jar filenames relevant to this CVE>"]
    }

    The "reasoning" field MUST use this markdown structure:

    ## CVE Summary\n\n<One sentence describing the vulnerability, e.g. "XXE injection via crafted PDF/XFA documents in Apache Tika's PDF parser.">\n\n## Reachability\n\n<Is the vulnerable code path reachable in Solr? Which modules use it and how?>\n\n## Exploitability\n\n<Can an adversary trigger the vulnerability? What access/config is needed?>

    If state is "affected" or "in_triage", also include:
    \n\n## Version Status\n\n<State which Solr versions are affected, e.g. "Solr 9.8.0 through 10.0.0 ship libraryX 1.2.3 which is vulnerable." and whether a fix is available in a newer Solr release.>\n\n## Recommended Action\n\n<Advice for END USERS of Solr, e.g. "Upgrade to Solr X.Y.Z which includes the fix" or "Apply the following workaround." Do NOT give advice to Solr maintainers about backporting or branch management.>

    If state is "not_affected", SKIP the Version Status and Recommended Action sections.

    IMPORTANT writing guidelines for the "reasoning" field:
    - Write for END USERS reading a public VEX document, not for Solr developers.
    - Say "Solr X.Y.Z ships libraryX 1.2.3" — do NOT mention Docker Scout, Docker
      images, lockfiles, gradle, git branches, or other internal tooling details.
    - In Version Status, refer to Solr release versions (e.g. "Solr 10.1.0"),
      not branch names (e.g. "branch_10x").
    - In Recommended Action, advise users to upgrade Solr or apply workarounds.
      Do NOT advise maintainers to backport, merge, or bump dependencies.

    Use "in_triage" if you are uncertain and a human should review.
    Use "not_affected" only when you have strong evidence.
    Use "affected" if the vulnerability appears genuinely exploitable.
""")

LLM_USER_PROMPT_TEMPLATE = textwrap.dedent("""\
    Please analyze the following CVE(s) for exploitability in Apache Solr {solr_version}.
    All CVE(s) below affect the same package: {package}@{version}

    Recent Solr releases (from git tags — these are the ONLY versions that exist):
    {recent_releases}

    Dependency version status across development branches (NOT yet released):
    {branch_versions}

    {cve_details}

    Search the Solr source code to understand how Solr USES this library.
    You only need to research the library usage ONCE — then assess each CVE
    based on its specific vulnerability description.
    Focus on code paths, not on checking versions (the version info above is
    already authoritative).

    Respond with a JSON ARRAY containing one assessment per CVE, in order:
    [
      {{
        "cve_id": "CVE-...",
        "state": "not_affected" | "affected" | "in_triage",
        "justification": "...",
        "reasoning": "...",
        "affected_jars": ["..."]
      }},
      ...
    ]
""")

# ---------------------------------------------------------------------------
# LLM tool definitions (for Anthropic tool_use)
# ---------------------------------------------------------------------------

LLM_TOOLS = [
    {
        "name": "search_source_code",
        "description": (
            "Search Solr source code using grep. Returns matching lines. "
            "Use this to find imports, class usages, method calls, or "
            "configuration references related to the vulnerable dependency."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (passed to grep -E).",
                },
                "file_glob": {
                    "type": "string",
                    "description": 'File glob to filter (e.g. "*.java", "*.xml"). Default: all files.',
                    "default": "*",
                },
                "path": {
                    "type": "string",
                    "description": 'Subdirectory to search within (e.g. "solr/core/src"). Default: entire checkout.',
                    "default": ".",
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "read_file",
        "description": (
            "Read the contents of a file from the Solr source tree. "
            "Use this to inspect specific source files, build configs, or XML configs. "
            "Use start_line/end_line to read a specific range (e.g. after grep found a match)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path relative to Solr checkout root (e.g. 'solr/core/src/java/org/apache/solr/SomeClass.java').",
                },
                "start_line": {
                    "type": "integer",
                    "description": "First line to read (1-based). Default: 1.",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Last line to read (inclusive). Default: start_line + 200.",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_directory",
        "description": (
            "List files and directories at a given path in the Solr source tree. "
            "Use this to explore the project structure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path relative to Solr checkout root. Default: root.",
                    "default": ".",
                },
            },
            "required": [],
        },
    },
]

# ---------------------------------------------------------------------------
# Docker Scout scanning
# ---------------------------------------------------------------------------


def check_docker_scout():
    """Verify Docker Scout CLI is available."""
    try:
        result = subprocess.run(
            ["docker", "scout", "version"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            version_line = result.stdout.strip().split("\n")[0]
            log.info("Docker Scout found: %s", version_line)
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def _setup_analysis_worktree(solr_checkout, ref):
    """Create a temporary git worktree at the given ref for LLM code analysis."""
    import tempfile
    worktree_dir = tempfile.mkdtemp(prefix="solr-cve-analysis-")
    result = subprocess.run(
        ["git", "worktree", "add", "--detach", worktree_dir, ref],
        capture_output=True, text=True, timeout=30,
        cwd=solr_checkout,
    )
    if result.returncode != 0:
        log.warning("Could not create worktree at %s: %s", ref, result.stderr.strip())
        log.warning("Falling back to current working tree for code analysis")
        os.rmdir(worktree_dir)
        return solr_checkout
    log.info("Created analysis worktree at %s (ref: %s)", worktree_dir, ref)
    return worktree_dir


def _cleanup_analysis_worktree(solr_checkout, worktree_dir):
    """Remove the temporary analysis worktree."""
    if worktree_dir == solr_checkout:
        return  # wasn't a worktree
    try:
        subprocess.run(
            ["git", "worktree", "remove", "--force", worktree_dir],
            capture_output=True, text=True, timeout=15,
            cwd=solr_checkout,
        )
        log.debug("Removed analysis worktree %s", worktree_dir)
    except Exception as e:
        log.warning("Could not remove worktree %s: %s", worktree_dir, e)


def run_docker_scout(image):
    """Run Docker Scout CVE scan and return parsed SARIF JSON."""
    log.info("Scanning image: %s", image)
    cmd = ["docker", "scout", "cves", image, "--format", "sarif"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        raise RuntimeError(
            f"Docker Scout failed (exit {result.returncode}):\n{result.stderr}"
        )

    # Docker Scout prints status lines before JSON; find the first '{'
    stdout = result.stdout
    brace_idx = stdout.find("{")
    if brace_idx < 0:
        raise RuntimeError(
            f"No JSON found in Docker Scout output.\nstdout: {stdout[:500]}"
        )

    return json.loads(stdout[brace_idx:])


# ---------------------------------------------------------------------------
# Solr branch and version resolution
# ---------------------------------------------------------------------------


def resolve_solr_branches(solr_version):
    """
    Resolve which git branches are relevant for a given Solr version.

    Solr branch conventions:
      - 10.0.0 was released from branch_10_0 (bugfix branch)
      - branch_10x is the next minor (e.g. 10.1.0)
      - main is the next major (e.g. 11.0.0)

    Returns a dict mapping branch description to branch name, e.g.:
      For 10.0.0: {"release": "branch_10_0", "next_minor": "branch_10x",
                    "9.x": "branch_9x", "main": "main"}
      For 9.10.1: {"release": "branch_9_10", "next_minor": "branch_9x",
                    "10.x": "branch_10x", "main": "main"}
    """
    parts = solr_version.split(".")
    if len(parts) < 3:
        return {"main": "main"}

    major, minor = int(parts[0]), int(parts[1])
    branches = {}
    branches["release"] = f"branch_{major}_{minor}"
    branches["next_minor"] = f"branch_{major}x"
    # Include the adjacent major line (e.g. 9.x ↔ 10.x, 10.x ↔ 11.x)
    for adj in [major - 1, major + 1]:
        if adj >= 9 and adj != major:
            branches[f"{adj}.x"] = f"branch_{adj}x"
            break  # only include the closest active line
    branches["main"] = "main"
    return branches


def resolve_next_version(solr_version):
    """
    Determine the likely next release version.

    Rule: the next release will be a new minor on the same major.
    E.g. 10.0.0 → next is 10.1.0 (from branch_10x).
         10.1.0 → next is 10.2.0 (from branch_10x).
    """
    parts = solr_version.split(".")
    if len(parts) >= 3:
        major, minor = int(parts[0]), int(parts[1])
        return f"{major}.{minor + 1}.0"
    return "unknown"


def _resolve_git_ref(solr_checkout, branch):
    """Find a working git ref for a branch, preferring remote refs (more up-to-date)."""
    # Prefer remote refs — local branches are often stale
    for ref in [f"upstream/{branch}", f"origin/{branch}", branch]:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", ref],
            capture_output=True, text=True, timeout=5,
            cwd=solr_checkout,
        )
        if result.returncode == 0:
            return ref
    return None


def _get_dep_version_from_lockfiles(solr_checkout, group_artifact, branch):
    """
    Find a dependency's resolved version on a branch.

    Checks both lockfile formats:
      - gradle.lockfile (10.x+): group:artifact:version=configurations
      - versions.lock (9.x, Palantir): group:artifact:version (N constraints: hash)

    Returns (highest_version, [all_versions]) or (None, []).
    """
    try:
        ref = _resolve_git_ref(solr_checkout, branch)
        if not ref:
            return None, []

        versions = set()

        # Try gradle.lockfile first (10.x+)
        result = subprocess.run(
            ["git", "grep", "-h", f"^{group_artifact}:", ref, "--", "*/gradle.lockfile"],
            capture_output=True, text=True, timeout=10,
            cwd=solr_checkout,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                # Format: group:artifact:version=config1,config2,...
                parts = line.split("=")[0].split(":")
                if len(parts) >= 3:
                    versions.add(parts[2])

        # Also try versions.lock (9.x, Palantir format)
        if not versions:
            result = subprocess.run(
                ["git", "show", f"{ref}:versions.lock"],
                capture_output=True, text=True, timeout=10,
                cwd=solr_checkout,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith(f"{group_artifact}:"):
                        # Format: group:artifact:version (N constraints: hash)
                        ver = line.split("(")[0].strip().split(":")
                        if len(ver) >= 3:
                            versions.add(ver[2].strip())

        if versions:
            return sorted(versions)[-1], sorted(versions)
        return None, []
    except Exception as e:
        log.debug("Lockfile lookup failed for %s on %s: %s", group_artifact, branch, e)
        return None, []


def gather_branch_version_info(solr_checkout, package, solr_version):
    """
    Pre-gather dependency version info across Solr branches by reading lockfiles.

    Uses gradle.lockfile (authoritative resolved versions) rather than
    libs.versions.toml (which is only a floor / may miss transitive deps).

    Returns a formatted string for inclusion in the LLM prompt.
    """
    branches = resolve_solr_branches(solr_version)
    next_ver = resolve_next_version(solr_version)

    # package is "group:artifact" — exactly the format used in lockfiles
    group_artifact = package

    results = []
    found_any = False
    for label, branch in branches.items():
        version, all_versions = _get_dep_version_from_lockfiles(
            solr_checkout, group_artifact, branch
        )
        if version:
            found_any = True
            extra = f" (also seen: {', '.join(all_versions)})" if len(all_versions) > 1 else ""
            results.append(f"  {label} ({branch}): {group_artifact} = {version}{extra}")
        else:
            results.append(f"  {label} ({branch}): not found")

    if not found_any:
        return "(Could not determine dependency versions from lockfiles across branches)"

    header = f"(from lockfiles, next release likely: {next_ver} from {branches.get('next_minor', '?')})"
    return header + "\n" + "\n".join(results)


def _format_recent_releases(all_tags):
    """
    Format recent releases for LLM context, showing last 3 per major version line.

    Dynamically picks the two most recent major versions (e.g. 9.x and 10.x,
    or 10.x and 11.x once 11.0.0 is released).
    """
    if not all_tags:
        return "(unknown)"

    # Group by major version
    by_major = {}
    for tag in all_tags:
        major = tag.split(".")[0]
        by_major.setdefault(major, []).append(tag)

    # Pick the two highest major versions
    majors = sorted(by_major.keys(), key=int, reverse=True)[:2]

    parts = []
    for major in sorted(majors, key=int):
        releases = by_major[major]
        last_3 = releases[-3:]
        parts.append(f"{major}.x: {', '.join(last_3)}")

    return " | ".join(parts) + f" (latest: {all_tags[-1]})"


# ---------------------------------------------------------------------------
# Affected Solr version range (from release tags)
# ---------------------------------------------------------------------------


def get_release_tags(solr_checkout):
    """Get sorted list of Solr release version strings from git tags."""
    try:
        result = subprocess.run(
            ["git", "tag", "-l", "releases/solr/*"],
            capture_output=True, text=True, timeout=10,
            cwd=solr_checkout,
        )
        if result.returncode != 0:
            return []
        tags = []
        for line in result.stdout.strip().split("\n"):
            ver = line.replace("releases/solr/", "")
            # Only include proper semver-ish versions (skip RCs, etc.)
            if ver and ver[0].isdigit() and ver.count(".") >= 2:
                tags.append(ver)
        # Sort by version components
        tags.sort(key=lambda v: [int(x) for x in v.split(".")[:3] if x.isdigit()])
        return tags
    except Exception as e:
        log.debug("Failed to list release tags: %s", e)
        return []


def get_dep_version_at_tag(solr_checkout, tag, group_artifact):
    """
    Look up a dependency's version at a specific Solr release tag.

    Handles both formats:
      - 10.x+: gradle.lockfile (group:artifact:version=configs)
      - 9.x:   versions.lock  (group:artifact:version (N constraints: hash))
    """
    ref = f"releases/solr/{tag}"

    try:
        # Try gradle.lockfile first (10.x+)
        result = subprocess.run(
            ["git", "grep", "-h", f"^{group_artifact}:", ref, "--", "*/gradle.lockfile"],
            capture_output=True, text=True, timeout=10,
            cwd=solr_checkout,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                parts = line.split("=")[0].split(":")
                if len(parts) >= 3:
                    return parts[2]

        # Fall back to versions.lock (9.x, Palantir format)
        result = subprocess.run(
            ["git", "show", f"{ref}:versions.lock"],
            capture_output=True, text=True, timeout=10,
            cwd=solr_checkout,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if line.startswith(f"{group_artifact}:"):
                    # Format: group:artifact:version (N constraints: hash)
                    parts = line.split("(")[0].strip().split(":")
                    if len(parts) >= 3:
                        return parts[2].strip()

        return None
    except Exception as e:
        log.debug("Version lookup failed for %s at tag %s: %s", group_artifact, tag, e)
        return None


def _parse_version(version_str):
    """Parse a version string, handling Maven suffixes like .Final, .Alpha1, -M3."""
    from packaging.version import Version, InvalidVersion
    # Strip common Maven qualifiers that packaging doesn't understand
    cleaned = re.sub(r"\.(Final|Release)$", "", version_str, flags=re.IGNORECASE)
    cleaned = re.sub(r"\.Alpha(\d+)$", r"a\1", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\.Beta(\d+)$", r"b\1", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\.CR(\d+)$", r"rc\1", cleaned, flags=re.IGNORECASE)
    try:
        return Version(cleaned)
    except InvalidVersion:
        return None


def is_version_in_range(version_str, range_str):
    """
    Check if a version falls within a SARIF affected_version range.

    Range format examples:
      "<2.5.9"                          → version < 2.5.9
      "<=4.2.12.Final"                  → version <= 4.2.12.Final
      ">=1.0,<=1.10.1"                  → 1.0 <= version <= 1.10.1
      ">=4.2.0.Alpha1,<4.2.10.Final"    → 4.2.0a1 <= version < 4.2.10
      ">=0"                             → all versions
    """
    ver = _parse_version(version_str)
    if ver is None:
        log.debug("Could not parse version: %s", version_str)
        return False
    if not range_str:
        return False

    for constraint in range_str.split(","):
        constraint = constraint.strip()
        if not constraint:
            continue

        if constraint.startswith("<="):
            bound = _parse_version(constraint[2:])
            if bound is not None and not (ver <= bound):
                return False
        elif constraint.startswith("<"):
            bound = _parse_version(constraint[1:])
            if bound is not None and not (ver < bound):
                return False
        elif constraint.startswith(">="):
            bound = _parse_version(constraint[2:])
            if bound is not None and not (ver >= bound):
                return False
        elif constraint.startswith(">"):
            bound = _parse_version(constraint[1:])
            if bound is not None and not (ver > bound):
                return False
        elif constraint.startswith("="):
            bound = _parse_version(constraint[1:])
            if bound is not None and not (ver == bound):
                return False

    return True


def compute_affected_version_range(solr_checkout, group_artifact, affected_range, scanned_version):
    """
    Walk release tags to find the range of Solr versions affected by a vulnerable dependency.

    Uses the CVE's affected version range (from SARIF) to check each Solr release,
    not just exact version matching.

    Returns a free-text string like "9.8.0–10.0.0" for use in VEX versions field.
    """
    tags = get_release_tags(solr_checkout)
    if not tags:
        return scanned_version

    if scanned_version not in tags:
        return scanned_version

    scanned_idx = tags.index(scanned_version)

    # Walk backwards from scanned version to find the first affected version
    first_affected = scanned_version
    for i in range(scanned_idx - 1, -1, -1):
        tag = tags[i]
        dep_ver = get_dep_version_at_tag(solr_checkout, tag, group_artifact)
        if dep_ver is None:
            break  # dependency not present in this version
        if affected_range and is_version_in_range(dep_ver, affected_range):
            first_affected = tag
        else:
            break  # dep present but not in vulnerable range

    if first_affected == scanned_version:
        return scanned_version
    return f"{first_affected}–{scanned_version}"


# ---------------------------------------------------------------------------
# SARIF filtering
# ---------------------------------------------------------------------------


def extract_purl_type(purl):
    """Extract package type from a PURL string (e.g. 'maven' from 'pkg:maven/...')."""
    m = re.match(r"pkg:([^/]+)/", purl)
    return m.group(1) if m else None


def extract_purl_coords(purl):
    """Extract group:artifact and version from a Maven PURL."""
    m = re.match(r"pkg:maven/([^@]+)@([^?]+)", purl)
    if m:
        return m.group(1).replace("/", ":"), m.group(2)
    return purl, ""


def filter_app_cves(sarif, severities):
    """
    Filter SARIF results to application-level (Maven) CVEs of given severities.

    Returns a list of dicts with keys:
      cve_id, package, version, severity, cvss_score, description, urls
    """
    severities_upper = {s.upper() for s in severities}
    results = []
    seen_cves = set()

    for run in sarif.get("runs", []):
        # Build rule lookup for descriptions
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule["id"]] = rule

        for finding in run.get("results", []):
            rule_id = finding.get("ruleId", "")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})

            # Severity filter
            severity = props.get("cvssV3_severity", "").upper()
            if severity not in severities_upper:
                continue

            # Package type filter: keep only Maven (application-level)
            purls = props.get("purls", [])
            maven_purls = [p for p in purls if extract_purl_type(p) == "maven"]
            if not maven_purls:
                continue

            if rule_id in seen_cves:
                continue
            seen_cves.add(rule_id)

            package, version = extract_purl_coords(maven_purls[0])
            cvss_score = props.get("security-severity", "N/A")
            description = rule.get("shortDescription", {}).get("text", "")
            help_text = rule.get("help", {}).get("text", "")
            if help_text and len(help_text) > len(description):
                description = help_text
            help_uri = rule.get("helpUri", "")

            results.append({
                "cve_id": rule_id,
                "package": package,
                "version": version,
                "severity": severity,
                "cvss_score": cvss_score,
                "description": description[:2000],  # truncate very long descriptions
                "urls": help_uri,
                "affected_version_range": props.get("affected_version", ""),
            })

    log.info(
        "Found %d application-level %s CVEs",
        len(results),
        "/".join(sorted(severities_upper)),
    )
    return results


# ---------------------------------------------------------------------------
# VEX and PR cross-referencing
# ---------------------------------------------------------------------------

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def fetch_existing_vex_cves(solr_site_repo, vex_url=None):
    """
    Fetch covered CVE IDs from the Solr VEX JSON.

    Primary: reads from the asf-staging branch of solr-site via gh API
    (reflects all merged VEX articles, no production lag).
    Fallback: HTTP GET from the published URL.
    """
    # Try gh api against asf-staging (most up-to-date)
    try:
        cmd = [
            "gh", "api",
            f"repos/{solr_site_repo}/contents/output/solr.vex.json?ref=asf-staging",
            "-H", "Accept: application/vnd.github.raw+json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip().startswith("{"):
            vex = json.loads(result.stdout)
            cves = set()
            for vuln in vex.get("vulnerabilities", []):
                vid = vuln.get("id", "")
                if vid:
                    cves.add(vid)
            log.info("Found %d vulnerabilities in VEX (from %s asf-staging)", len(cves), solr_site_repo)
            return cves
    except Exception as e:
        log.debug("gh api VEX fetch failed: %s", e)

    # Fallback: HTTP GET from published URL
    if vex_url:
        try:
            log.info("Falling back to published VEX at %s", vex_url)
            resp = requests.get(vex_url, timeout=30)
            resp.raise_for_status()
            vex = resp.json()
            cves = set()
            for vuln in vex.get("vulnerabilities", []):
                vid = vuln.get("id", "")
                if vid:
                    cves.add(vid)
            log.info("Found %d vulnerabilities in published VEX", len(cves))
            return cves
        except Exception as e:
            log.warning("Could not fetch VEX file: %s (continuing with empty set)", e)

    return set()


def fetch_open_pr_cves(repo):
    """Find CVE IDs mentioned in open solr-site PRs using the gh CLI."""
    try:
        cmd = [
            "gh", "pr", "list",
            "--repo", repo,
            "--search", "VEX: CVE in:title",
            "--state", "open",
            "--json", "title",
            "--limit", "200",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            log.warning("gh pr list failed: %s", result.stderr.strip())
            return set()

        prs = json.loads(result.stdout)
        cves = set()
        for pr in prs:
            # Extract CVE IDs from PR title only (title format: "VEX: CVE-XXXX-XXXXX")
            cves.update(CVE_PATTERN.findall(pr.get("title", "")))
        log.info("Found %d CVEs in open VEX PRs on %s", len(cves), repo)
        return cves
    except Exception as e:
        log.warning("Could not query open PRs: %s (continuing with empty set)", e)
        return set()


def scan_local_vex_dir(output_dir):
    """Scan a local directory for existing VEX markdown files and extract CVE IDs."""
    cves = set()
    if not output_dir or not os.path.isdir(output_dir):
        return cves
    for fname in os.listdir(output_dir):
        if fname.endswith(".md"):
            cves.update(CVE_PATTERN.findall(fname))
            # Also check YAML front matter for cve: field
            try:
                fpath = os.path.join(output_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read(1000)  # front matter is at the top
                cves.update(CVE_PATTERN.findall(content))
            except Exception as e:
                log.debug("Could not read VEX file %s: %s", fname, e)
    if cves:
        log.info("Found %d CVEs in local VEX files in %s", len(cves), output_dir)
    return cves


# ---------------------------------------------------------------------------
# LLM-based CVE analysis
# ---------------------------------------------------------------------------


def _validate_path(solr_checkout, relative_path):
    """Validate that a relative path stays within the Solr checkout. Returns absolute path or None."""
    resolved = os.path.realpath(os.path.join(solr_checkout, relative_path))
    if not resolved.startswith(os.path.realpath(solr_checkout)):
        return None
    return resolved


def _execute_tool(tool_name, tool_input, solr_checkout):
    """Execute a tool call from the LLM and return the result string."""
    try:
        if tool_name == "search_source_code":
            pattern = tool_input["pattern"]
            file_glob = tool_input.get("file_glob", "*")
            path = tool_input.get("path", ".")
            search_dir = _validate_path(solr_checkout, path)
            if not search_dir:
                return "Error: path escapes the Solr checkout directory."
            cmd = ["grep", "-rn", "--include", file_glob, "-E", pattern, search_dir]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            raw_lines = result.stdout.split("\n")
            # Strip the solr_checkout prefix from paths for cleaner output
            prefix = solr_checkout.rstrip("/") + "/"
            cleaned = []
            for line in raw_lines:
                if line.startswith(prefix):
                    line = line[len(prefix):]
                cleaned.append(line)

            # Deduplicate by file — show at most 5 matches per file to save context
            file_counts = {}
            compact = []
            for line in cleaned:
                if not line.strip():
                    continue
                fname = line.split(":")[0] if ":" in line else ""
                file_counts[fname] = file_counts.get(fname, 0) + 1
                if file_counts[fname] <= 5:
                    compact.append(line)
                elif file_counts[fname] == 6:
                    compact.append(f"  ... (more matches in {fname})")

            total = len([l for l in cleaned if l.strip()])
            if not compact:
                return "No matches found."
            output = "\n".join(compact[:40])
            if total > 40:
                # Provide a summary of which files matched
                file_summary = ", ".join(
                    f"{f} ({c})" for f, c in sorted(file_counts.items(), key=lambda x: -x[1])[:10]
                )
                output += f"\n\n[{total} total matches across {len(file_counts)} files: {file_summary}]"
            return output

        elif tool_name == "read_file":
            filepath = _validate_path(solr_checkout, tool_input["path"])
            if not filepath:
                return "Error: path escapes the Solr checkout directory."
            if not os.path.isfile(filepath):
                return f"Error: file not found: {tool_input['path']}"
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
            total = len(all_lines)
            start = max(0, tool_input.get("start_line", 1) - 1)  # 1-based to 0-based
            # end_line is 1-based inclusive; convert to 0-based exclusive for slice
            if "end_line" in tool_input:
                end = tool_input["end_line"]  # 1-based inclusive → 0-based exclusive
            else:
                end = start + 200
            end = min(end, start + 200)  # cap at 200 lines per read
            lines = all_lines[start:end]
            header = f"[lines {start + 1}-{min(end, total)} of {total}]\n"
            return header + "".join(lines)

        elif tool_name == "list_directory":
            dirpath = _validate_path(solr_checkout, tool_input.get("path", "."))
            if not dirpath:
                return "Error: path escapes the Solr checkout directory."
            if not os.path.isdir(dirpath):
                return f"Error: directory not found: {tool_input.get('path', '.')}"
            entries = sorted(os.listdir(dirpath))
            return "\n".join(entries[:200])

        else:
            return f"Error: unknown tool '{tool_name}'"

    except subprocess.TimeoutExpired:
        return "Error: command timed out."
    except Exception as e:
        return f"Error: {e}"


def _llm_create_with_retry(client, max_retries=5, **kwargs):
    """Call client.messages.create with retry on rate-limit (429) errors."""
    for attempt in range(max_retries):
        try:
            return client.messages.create(**kwargs)
        except anthropic.RateLimitError as e:
            if attempt == max_retries - 1:
                raise
            # Check for retry-after header hint, otherwise exponential backoff
            wait = min(2 ** attempt * 30, 120)  # 30s, 60s, 120s, 120s
            print(f"    ⏳ Rate limited, waiting {wait}s before retry ({attempt + 1}/{max_retries})...")
            time.sleep(wait)


def _force_conclusion(client, model, messages, total_input_tokens, total_output_tokens, reason):
    """Send a final prompt forcing the LLM to conclude with its findings so far."""
    print(f"    ⚠️  {reason} — forcing conclusion...")
    messages.append({"role": "user", "content": (
        "STOP researching. You have gathered enough information. "
        "Based on everything you have found so far, provide your final "
        "assessment NOW. Respond with ONLY the JSON array."
    )})
    response = _llm_create_with_retry(
        client,
        model=model,
        max_tokens=4096,
        system=LLM_SYSTEM_PROMPT,
        messages=messages,
    )
    text_blocks = [b.text for b in response.content if b.type == "text"]
    final_text = "\n".join(text_blocks)
    total_input_tokens += response.usage.input_tokens
    total_output_tokens += response.usage.output_tokens
    print(f"    📊 Tokens used: {total_input_tokens:,} in / {total_output_tokens:,} out")
    return final_text, total_input_tokens, total_output_tokens


def _format_cve_details(cves):
    """Format CVE details for inclusion in a grouped LLM prompt."""
    parts = []
    for i, cve in enumerate(cves, 1):
        parts.append(
            f"--- CVE {i} of {len(cves)} ---\n"
            f"CVE ID: {cve['cve_id']}\n"
            f"Severity: {cve['severity']} (CVSS: {cve['cvss_score']})\n"
            f"Description: {cve['description']}\n"
            f"Advisory URL: {cve['urls']}"
        )
    return "\n\n".join(parts)


def _parse_grouped_llm_response(text, cves):
    """Parse the LLM's JSON array response for a group of CVEs."""
    # Try to extract JSON array from the response
    json_match = re.search(r"\[[\s\S]*\]", text)
    if json_match:
        try:
            data = json.loads(json_match.group())
            if isinstance(data, list):
                # Build a lookup by cve_id
                results_by_id = {}
                for item in data:
                    cve_id = item.get("cve_id", "")
                    results_by_id[cve_id] = _sanitize_analysis({
                        "state": item.get("state", "in_triage"),
                        "justification": item.get("justification", ""),
                        "reasoning": item.get("reasoning", ""),
                        "affected_jars": item.get("affected_jars", []),
                        "llm_analyzed": True,
                    })
                # Return results in the same order as input CVEs
                results = []
                for cve in cves:
                    if cve["cve_id"] in results_by_id:
                        results.append(results_by_id[cve["cve_id"]])
                    else:
                        results.append(_parse_llm_response(text, cve))
                return results
        except json.JSONDecodeError:
            pass

    # Fallback: try parsing as a single object (for single-CVE groups)
    if len(cves) == 1:
        return [_parse_llm_response(text, cves[0])]

    # Last resort: mark all as in_triage
    log.warning("Could not parse grouped LLM response, marking all as in_triage")
    return [{
        "state": "in_triage",
        "justification": "",
        "reasoning": text,
        "affected_jars": [],
        "llm_analyzed": True,
    } for _ in cves]


def analyze_cve_group_with_llm(cves, solr_checkout, api_key, model, solr_version,
                               max_iterations=25, max_input_tokens=200000,
                               branch_versions="", recent_releases=""):
    """
    Analyze a group of CVEs for the same package in a single LLM session.

    The LLM researches the library usage once, then assesses each CVE.

    Returns a list of dicts (one per CVE) with keys:
        state, justification, reasoning, affected_jars, llm_analyzed,
        input_tokens, output_tokens.
    """
    client = anthropic.Anthropic(api_key=api_key)

    cve_details = _format_cve_details(cves)
    user_prompt = LLM_USER_PROMPT_TEMPLATE.format(
        solr_version=solr_version,
        package=cves[0]["package"],
        version=cves[0]["version"],
        cve_details=cve_details,
        branch_versions=branch_versions or "(version info not available)",
        recent_releases=recent_releases or "(not available)",
    )

    messages = [{"role": "user", "content": user_prompt}]
    total_input_tokens = 0
    total_output_tokens = 0
    iteration = 0

    while True:
        iteration += 1
        response = _llm_create_with_retry(
            client,
            model=model,
            max_tokens=8192,
            system=LLM_SYSTEM_PROMPT,
            tools=LLM_TOOLS,
            messages=messages,
        )

        # Track token usage
        total_input_tokens += response.usage.input_tokens
        total_output_tokens += response.usage.output_tokens

        # Print any thinking/text blocks the LLM emits alongside tool calls
        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(f"    💭 {block.text.strip()}")

        # Check if the LLM wants to use tools
        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if not tool_use_blocks:
            # Final response — extract text
            text_blocks = [b.text for b in response.content if b.type == "text"]
            final_text = "\n".join(text_blocks)
            print(f"    📊 Tokens used: {total_input_tokens:,} in / {total_output_tokens:,} out "
                  f"({iteration} iteration(s), {len(cves)} CVEs)")
            results = _parse_grouped_llm_response(final_text, cves)
            for r in results:
                r["input_tokens"] = total_input_tokens // len(cves)
                r["output_tokens"] = total_output_tokens // len(cves)
            return results

        # Execute tool calls and print what the agent is doing
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for tool_block in tool_use_blocks:
            _print_tool_call(iteration, tool_block)
            result_str = _execute_tool(
                tool_block.name, tool_block.input, solr_checkout
            )
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_block.id,
                "content": result_str,
            })
        messages.append({"role": "user", "content": tool_results})

        # Check limits — force a conclusion if exceeded
        limit_reason = None
        if total_input_tokens >= max_input_tokens:
            limit_reason = (f"Token budget reached ({total_input_tokens:,} >= "
                            f"{max_input_tokens:,}) after {iteration} iterations")
        elif iteration >= max_iterations:
            limit_reason = f"Iteration limit reached ({iteration} >= {max_iterations})"
        if limit_reason:
            final_text, total_input_tokens, total_output_tokens = _force_conclusion(
                client, model, messages,
                total_input_tokens, total_output_tokens, limit_reason,
            )
            results = _parse_grouped_llm_response(final_text, cves)
            for r in results:
                # Forced conclusion = incomplete analysis → always in_triage
                r["state"] = "in_triage"
                r["justification"] = ""
                r["input_tokens"] = total_input_tokens // len(cves)
                r["output_tokens"] = total_output_tokens // len(cves)
            return results


def _print_tool_call(iteration, tool_block):
    """Print a human-readable summary of what tool the LLM is calling."""
    name = tool_block.name
    inp = tool_block.input
    if name == "search_source_code":
        detail = inp.get("pattern", "")
        if inp.get("file_glob") and inp["file_glob"] != "*":
            detail += f" ({inp['file_glob']})"
        if inp.get("path") and inp["path"] != ".":
            detail += f" in {inp['path']}"
        print(f"    🔍 [{iteration}] Searching: {detail}")
    elif name == "read_file":
        detail = inp.get("path", "?")
        if inp.get("start_line"):
            detail += f" (lines {inp['start_line']}-{inp.get('end_line', '?')})"
        print(f"    📄 [{iteration}] Reading: {detail}")
    elif name == "list_directory":
        print(f"    📂 [{iteration}] Listing: {inp.get('path', '.')}")
    else:
        print(f"    🔧 [{iteration}] {name}: {json.dumps(inp)[:100]}")


def _sanitize_analysis(result):
    """Ensure state and justification are consistent per CycloneDX rules."""
    state = result.get("state", "in_triage")
    # justification is only valid for not_affected
    if state != "not_affected":
        result["justification"] = ""
    # not_affected requires a justification
    if state == "not_affected" and not result.get("justification"):
        result["justification"] = "vulnerable_code_not_reachable"
    return result


def _parse_llm_response(text, cve):
    """Parse the LLM's JSON response, with fallback to in_triage."""
    # Try to extract JSON from the response (may have surrounding text)
    json_match = re.search(r"\{[\s\S]*\}", text)
    if json_match:
        try:
            data = json.loads(json_match.group())
            return _sanitize_analysis({
                "state": data.get("state", "in_triage"),
                "justification": data.get("justification", ""),
                "reasoning": data.get("reasoning", text),
                "affected_jars": data.get("affected_jars", []),
                "llm_analyzed": True,
            })
        except json.JSONDecodeError:
            pass

    log.warning("Could not parse LLM JSON for %s, marking as in_triage", cve["cve_id"])
    return {
        "state": "in_triage",
        "justification": "",
        "reasoning": text,
        "affected_jars": [],
        "llm_analyzed": True,
    }


# ---------------------------------------------------------------------------
# VEX markdown generation
# ---------------------------------------------------------------------------


def generate_vex_markdown(cve, analysis, solr_version):
    """Generate a VEX article in solr-site markdown format."""
    version_range = analysis.get("version_range", solr_version)
    front_matter = {
        "cve": cve["cve_id"],
        "category": ["solr/vex"],
        "versions": version_range,
        "analysis": {"state": analysis["state"]},
        "title": f"{cve['package']}: {cve['cve_id']}",
    }

    if analysis.get("justification"):
        front_matter["analysis"]["justification"] = analysis["justification"]

    jars = analysis.get("affected_jars", [])
    if jars:
        front_matter["jars"] = jars

    yaml_str = yaml.dump(front_matter, default_flow_style=False, sort_keys=False)

    # Body depends on whether LLM analysis was performed
    llm_analyzed = analysis.get("llm_analyzed", False)
    body_parts = []

    if llm_analyzed:
        # LLM-analyzed: the reasoning IS the body
        body_parts.append(analysis.get("reasoning", "Manual review needed."))
    else:
        # No LLM: include CVE metadata for human context
        body_parts.append(
            f"**{cve['severity']}** (CVSS: {cve['cvss_score']}) — "
            f"`{cve['package']}@{cve['version']}`"
        )
        if cve.get("description"):
            body_parts.append("")
            body_parts.append(cve["description"])
        if cve.get("urls"):
            body_parts.append("")
            body_parts.append(f"Reference: {cve['urls']}")

    return f"---\n{yaml_str}---\n\n" + "\n".join(body_parts) + "\n"


def vex_filename(cve_id):
    """Generate the VEX article filename."""
    today = date.today().isoformat()
    cve_slug = cve_id.lower()
    return f"{today}-{cve_slug}.md"


# ---------------------------------------------------------------------------
# PR creation
# ---------------------------------------------------------------------------


def create_vex_pr(cve_id, markdown_content, solrbot_token, fork_repo, target_repo, reviewers):
    """Create a VEX PR on solr-site via the solrbot fork."""
    from github import Github, GithubException  # imported here; checked by _check_imports()

    gh = Github(solrbot_token)
    fork = gh.get_repo(fork_repo)
    target = gh.get_repo(target_repo)

    # Get default branch SHA from target
    default_branch = target.default_branch
    base_ref = target.get_git_ref(f"heads/{default_branch}")
    base_sha = base_ref.object.sha

    branch_name = f"vex/{cve_id.lower()}"
    filename = vex_filename(cve_id)
    file_path = f"content/solr/vex/{filename}"

    # Create branch on fork
    try:
        fork.create_git_ref(f"refs/heads/{branch_name}", base_sha)
        log.info("Created branch %s on %s", branch_name, fork_repo)
    except GithubException as e:
        if e.status == 422:  # already exists
            log.info("Branch %s already exists on %s", branch_name, fork_repo)
        else:
            raise

    # Create file on the branch
    fork.create_file(
        path=file_path,
        message=f"Add VEX entry for {cve_id}",
        content=markdown_content,
        branch=branch_name,
    )

    # Create PR from fork to upstream
    fork_owner = fork_repo.split("/")[0]
    pr = target.create_pull(
        title=f"VEX: {cve_id}",
        body=(
            f"Automated VEX triage for **{cve_id}**.\n\n"
            f"Generated by `cve_triage.py`. Please review the analysis.\n"
        ),
        head=f"{fork_owner}:{branch_name}",
        base=default_branch,
    )
    log.info("Created PR #%d: %s", pr.number, pr.html_url)

    # Add reviewers
    if reviewers:
        try:
            pr.create_review_request(reviewers=reviewers)
        except GithubException as e:
            log.warning("Could not set reviewers: %s", e)

    return pr.html_url


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------

EPILOG = """\
environment variables:
  ANTHROPIC_API_KEY       API key for LLM analysis (required unless --skip-llm)
  GITHUB_TOKEN            GitHub token for read access (optional, for API rate limits)
  SOLRBOT_GITHUB_TOKEN    Token for solrbot to create PRs on solr-site fork
                          (required only when creating PRs, not with --dry-run or --output-dir)

examples:
  # Just list unresolved CVEs:
  %(prog)s --solr-version 10.0.0 --dry-run

  # Analyze with LLM, write VEX files locally:
  %(prog)s --solr-version 10.0.0 --output-dir ./vex-output/

  # Full run: analyze and create PRs:
  %(prog)s --solr-version 10.0.0 --reviewers "committer1,committer2"
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated CVE triage for Apache Solr Docker images.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--solr-version", required=True,
        help="Solr version to scan (e.g. 10.0.0)",
    )
    parser.add_argument(
        "--docker-image", default=None,
        help='Docker image to scan. Default: "registry://docker.io/solr:{version}"',
    )
    parser.add_argument(
        "--solr-checkout", default=".",
        help="Path to local Solr source checkout for LLM code analysis (default: cwd)",
    )
    parser.add_argument(
        "--solr-branch", default=None,
        help="Git branch to use for code analysis. Default: auto-resolve from version "
             "(e.g. 10.0.0 uses branch_10_0). The checkout is NOT switched — this only "
             "affects which branch is used for version lookups.",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Write VEX markdown files to this directory instead of creating PRs",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print results to console only; do not write files or create PRs",
    )
    parser.add_argument(
        "--skip-llm", action="store_true",
        help="Skip LLM analysis; just report unresolved CVEs",
    )
    parser.add_argument(
        "--solr-site-repo", default="apache/solr-site",
        help="Target repository for VEX PRs (default: apache/solr-site)",
    )
    parser.add_argument(
        "--solr-site-fork", default="solrbot/solr-site",
        help="Fork repository to push VEX branches to (default: solrbot/solr-site)",
    )
    parser.add_argument(
        "--vex-url", default="https://solr.apache.org/solr.vex.json",
        help="URL to published Solr VEX JSON (default: https://solr.apache.org/solr.vex.json)",
    )
    parser.add_argument(
        "--reviewers", default="",
        help="Comma-separated GitHub usernames to request review on PRs",
    )
    parser.add_argument(
        "--model", default="best",
        choices=["best", "balanced", "fast"],
        help="LLM quality/cost tradeoff: best (Opus, most capable, default), "
             "balanced (Sonnet, cheaper), fast (Haiku, cheapest/fastest)",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=25,
        help="Max LLM tool-use iterations per CVE before forcing conclusion (default: 25)",
    )
    parser.add_argument(
        "--max-input-tokens", type=int, default=200000,
        help="Input token budget per CVE; agent is forced to conclude when exceeded (default: 200000)",
    )
    parser.add_argument(
        "--max-cves", type=int, default=10,
        help="Maximum number of new CVEs to analyze per run (default: 10)",
    )
    parser.add_argument(
        "--cves", default=None,
        help="Only analyze these CVE(s), comma-separated (e.g. CVE-2026-42027,CVE-2026-40682). "
             "Skips the VEX/PR deduplication filters.",
    )
    parser.add_argument(
        "--severity", default="CRITICAL,HIGH",
        help="Comma-separated severity levels to include (default: CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose/debug logging",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    need_llm = not args.skip_llm
    need_github = not (args.dry_run or args.output_dir)
    _check_imports(need_llm=need_llm, need_github=need_github)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    # Suppress noisy HTTP request logs from the Anthropic SDK
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)

    # Resolve paths
    solr_checkout = os.path.realpath(args.solr_checkout)
    if not os.path.isdir(solr_checkout):
        log.error("Solr checkout not found: %s", solr_checkout)
        sys.exit(1)

    # Check Docker Scout
    if not check_docker_scout():
        log.error(
            "Docker Scout CLI not found. Install it:\n"
            "  curl -fsSL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh"
        )
        sys.exit(1)

    # Determine image
    image = args.docker_image or f"registry://docker.io/solr:{args.solr_version}"
    severities = [s.strip() for s in args.severity.split(",")]

    # Step 1: Scan
    print(f"=== Scanning {image} for CVEs ===")
    sarif = run_docker_scout(image)

    # Step 2: Filter to app-level CVEs
    cves = filter_app_cves(sarif, severities)
    if not cves:
        print("No application-level CRITICAL/HIGH CVEs found. Done.")
        sys.exit(0)

    print(f"Found {len(cves)} application-level {args.severity} CVE(s)")

    # Step 3: Filter CVEs
    if args.cves:
        # Selective mode: only analyze specified CVEs, skip deduplication
        selected = {c.strip() for c in args.cves.split(",")}
        new_cves = [c for c in cves if c["cve_id"] in selected]
        missing = selected - {c["cve_id"] for c in new_cves}
        if missing:
            log.warning("Requested CVEs not found in scan results: %s", ", ".join(sorted(missing)))
        skipped = len(cves) - len(new_cves)
        print(f"Selected {len(new_cves)} CVE(s) by --cves filter")
    else:
        # Normal mode: cross-reference with existing VEX and open PRs
        existing_vex = fetch_existing_vex_cves(args.solr_site_repo, vex_url=args.vex_url)
        open_pr_cves = fetch_open_pr_cves(args.solr_site_repo)
        local_vex_cves = scan_local_vex_dir(args.output_dir) if args.output_dir else set()
        already_covered = existing_vex | open_pr_cves | local_vex_cves
        new_cves = [c for c in cves if c["cve_id"] not in already_covered]
        skipped = len(cves) - len(new_cves)
        if skipped:
            print(f"Skipped {skipped} CVE(s) already covered by VEX or open PRs")

    # Sort by severity (CRITICAL first) then by CVSS score descending
    _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    new_cves.sort(key=lambda c: (
        _severity_order.get(c["severity"], 9),
        -float(c["cvss_score"]) if c["cvss_score"] != "N/A" else 0,
    ))

    if not new_cves:
        print("All CVEs are already covered. Nothing to do.")
        sys.exit(0)

    print(f"\n=== {len(new_cves)} new CVE(s) to triage ===")
    for c in new_cves:
        print(f"  {c['cve_id']}  {c['severity']}  {c['package']}@{c['version']}")

    # Determine git ref for LLM code analysis tools
    analysis_ref = args.solr_branch or f"releases/solr/{args.solr_version}"
    # Create a temporary worktree at the analysis ref so tools can read files directly
    analysis_checkout = _setup_analysis_worktree(solr_checkout, analysis_ref)

    # Get recent releases for LLM context (so it doesn't reference unreleased versions)
    # Show last 3 per major version line to cover both 9.x and 10.x
    all_tags = get_release_tags(solr_checkout)
    recent_releases = _format_recent_releases(all_tags)

    # Step 4: Group CVEs by package for efficient analysis
    cves_to_analyze = new_cves[:args.max_cves]
    groups = {}
    for c in cves_to_analyze:
        key = f"{c['package']}@{c['version']}"
        groups.setdefault(key, []).append(c)

    group_count = len(groups)
    cve_count = len(cves_to_analyze)
    if group_count < cve_count:
        print(f"\nGrouped {cve_count} CVEs into {group_count} package group(s) for efficient analysis")

    analyzed = []
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    try:
        group_idx = 0
        for pkg_key, group_cves in groups.items():
            group_idx += 1
            cve_ids = ", ".join(c["cve_id"] for c in group_cves)
            package = group_cves[0]["package"]
            print(f"\n=== Group [{group_idx}/{group_count}]: {package} ({len(group_cves)} CVE(s): {cve_ids}) ===")

            # Compute affected Solr version range (local git, no LLM tokens)
            version_range = compute_affected_version_range(
                solr_checkout, group_cves[0]["package"],
                group_cves[0].get("affected_version_range", ""), args.solr_version,
            )
            print(f"    📋 Affected Solr versions: {version_range}")

            # Pre-gather branch fix status (local git, no LLM tokens)
            branch_versions = gather_branch_version_info(
                solr_checkout, group_cves[0]["package"], args.solr_version,
            )
            if branch_versions and "Could not" not in branch_versions:
                print(f"    📋 Branch fix status:\n{branch_versions}")

            if args.skip_llm:
                for c in group_cves:
                    analyzed.append((c, {
                        "state": "in_triage",
                        "justification": "",
                        "reasoning": "",
                        "affected_jars": [],
                        "llm_analyzed": False,
                        "version_range": version_range,
                    }))
                continue

            if not api_key:
                log.error(
                    "ANTHROPIC_API_KEY env var required for LLM analysis.\n"
                    "Use --skip-llm to skip, or set the env var."
                )
                sys.exit(1)

            model = MODEL_ALIASES.get(args.model, args.model)
            if group_idx == 1:
                print(f"Using model: {model}")

            try:
                results = analyze_cve_group_with_llm(
                    group_cves, analysis_checkout, api_key, model, args.solr_version,
                    max_iterations=args.max_iterations,
                    max_input_tokens=args.max_input_tokens,
                    branch_versions=branch_versions,
                    recent_releases=recent_releases,
                )
                for c, analysis in zip(group_cves, results):
                    analysis["version_range"] = version_range
                    analyzed.append((c, analysis))
                    print(f"  {c['cve_id']}: {analysis['state']}"
                          + (f" ({analysis['justification']})" if analysis.get('justification') else ""))
            except Exception as e:
                log.error("LLM analysis failed for group %s: %s", package, e)
                for c in group_cves:
                    analyzed.append((c, {
                        "state": "in_triage",
                        "justification": "",
                        "reasoning": f"Automated analysis failed: {e}",
                        "affected_jars": [],
                        "llm_analyzed": False,
                        "version_range": version_range,
                    }))
    finally:
        _cleanup_analysis_worktree(solr_checkout, analysis_checkout)

    if not analyzed:
        print("No CVEs were analyzed.")
        sys.exit(0)

    # Step 5: Output
    if args.dry_run:
        print("\n=== DRY RUN — Results ===")
        for cve, analysis in analyzed:
            md = generate_vex_markdown(cve, analysis, args.solr_version)
            print(f"\n--- {cve['cve_id']} ({analysis['state']}) ---")
            print(md)
        print("\nDry run complete. No files written, no PRs created.")

    elif args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        print(f"\n=== Writing VEX files to {args.output_dir} ===")
        for cve, analysis in analyzed:
            md = generate_vex_markdown(cve, analysis, args.solr_version)
            fname = vex_filename(cve["cve_id"])
            fpath = os.path.join(args.output_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"  Wrote {fpath}")
        print("Done.")

    else:
        # Create PRs
        solrbot_token = os.environ.get("SOLRBOT_GITHUB_TOKEN", "")
        if not solrbot_token:
            log.error(
                "SOLRBOT_GITHUB_TOKEN env var required to create PRs.\n"
                "Use --output-dir to write files locally, or --dry-run to preview."
            )
            sys.exit(1)

        reviewers = [r.strip() for r in args.reviewers.split(",") if r.strip()]
        print(f"\n=== Creating VEX PRs on {args.solr_site_repo} ===")
        for cve, analysis in analyzed:
            md = generate_vex_markdown(cve, analysis, args.solr_version)
            try:
                pr_url = create_vex_pr(
                    cve["cve_id"], md, solrbot_token,
                    args.solr_site_fork, args.solr_site_repo, reviewers,
                )
                print(f"  {cve['cve_id']}: {pr_url}")
            except Exception as e:
                log.error("Failed to create PR for %s: %s", cve["cve_id"], e)

    # Summary
    model = MODEL_ALIASES.get(args.model, args.model) if not args.skip_llm else None
    print("\n=== Summary ===")
    print(f"Image scanned:    {image}")
    print(f"Total app CVEs:   {len(cves)}")
    print(f"Already covered:  {skipped}")
    print(f"New CVEs:         {len(new_cves)}")
    print(f"Analyzed:         {len(analyzed)}")

    total_cost = 0.0
    for cve, analysis in analyzed:
        in_tok = analysis.get("input_tokens", 0)
        out_tok = analysis.get("output_tokens", 0)
        cost = estimate_cost(model, in_tok, out_tok) if model else None
        cost_str = f"  ${cost:.2f}" if cost else ""
        print(f"  {cve['cve_id']:20s}  {cve['severity']:8s}  {analysis['state']:15s}  {cve['package']}{cost_str}")
        if cost:
            total_cost += cost

    if total_cost > 0:
        print(f"\nEstimated LLM cost: ${total_cost:.2f} ({model})")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nReceived Ctrl-C, exiting early")
