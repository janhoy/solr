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
import shutil
import subprocess
import sys
import textwrap
import time
from datetime import date

# ---------------------------------------------------------------------------
# Lazy imports with helpful error messages
# ---------------------------------------------------------------------------

def _try_import(module_name, pip_name=None):
    """Import a module, return None if missing."""
    try:
        return __import__(module_name)
    except ImportError:
        return None


yaml = _try_import("yaml", "PyYAML")
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
    "best": "claude-opus-4-6",
    "balanced": "claude-sonnet-4-6",
    "fast": "claude-haiku-4-5-20251001",
}

# ---------------------------------------------------------------------------
# Prompt template for LLM CVE analysis
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a security analyst triaging CVEs for Apache Solr.

    You will be given details about a CVE affecting a Java dependency that ships
    with Solr. Your job is to determine whether the vulnerability is actually
    exploitable in the context of Apache Solr.

    You have tools to search Solr's source code. Use them to:
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
      "justification": "<one of: component_not_present, vulnerable_code_not_reachable, vulnerable_code_cannot_be_controlled_by_adversary, requires_configuration, requires_dependency, requires_environment, protected_by_mitigating_control>",
      "reasoning": "<detailed explanation of your analysis>",
      "affected_jars": ["<jar filenames relevant to this CVE>"]
    }

    Use "in_triage" if you are uncertain and a human should review.
    Use "not_affected" only when you have strong evidence.
    Use "affected" if the vulnerability appears genuinely exploitable.
""")

LLM_USER_PROMPT_TEMPLATE = textwrap.dedent("""\
    Please analyze the following CVE for exploitability in Apache Solr {solr_version}:

    CVE ID: {cve_id}
    Severity: {severity} (CVSS: {cvss_score})
    Affected Package: {package}
    Affected Version: {version}
    Description: {description}

    Advisory URLs:
    {urls}

    Search the Solr source code to determine if this vulnerability is exploitable.
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
                "purls": maven_purls,
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


def fetch_existing_vex_cves(vex_url):
    """Fetch the published Solr VEX JSON and extract covered CVE IDs."""
    try:
        log.info("Fetching published VEX from %s", vex_url)
        resp = requests.get(vex_url, timeout=30)
        resp.raise_for_status()
        vex = resp.json()
        cves = set()
        for vuln in vex.get("vulnerabilities", []):
            vid = vuln.get("id", "")
            if vid.startswith("CVE-"):
                cves.add(vid)
        log.info("Found %d CVEs already in published VEX", len(cves))
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
            "--search", "CVE",
            "--state", "open",
            "--json", "title,body",
            "--limit", "100",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            log.warning("gh pr list failed: %s", result.stderr.strip())
            return set()

        prs = json.loads(result.stdout)
        cves = set()
        for pr in prs:
            text = (pr.get("title", "") + " " + pr.get("body", ""))
            cves.update(CVE_PATTERN.findall(text))
        log.info("Found %d CVEs in open PRs on %s", len(cves), repo)
        return cves
    except Exception as e:
        log.warning("Could not query open PRs: %s (continuing with empty set)", e)
        return set()


# ---------------------------------------------------------------------------
# LLM-based CVE analysis
# ---------------------------------------------------------------------------


def _validate_path(solr_checkout, relative_path):
    """Validate that a relative path stays within the Solr checkout. Returns absolute path or None."""
    resolved = os.path.normpath(os.path.join(solr_checkout, relative_path))
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
            end = tool_input.get("end_line", start + 200)
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


def _force_conclusion(client, model, messages, cve, total_input_tokens, total_output_tokens, reason):
    """Send a final prompt forcing the LLM to conclude with its findings so far."""
    print(f"    ⚠️  {reason} — forcing conclusion...")
    messages.append({"role": "user", "content": (
        "STOP researching. You have gathered enough information. "
        "Based on everything you have found so far, provide your final "
        "assessment NOW. Respond with ONLY the JSON object."
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
    return _parse_llm_response(final_text, cve)


def analyze_cve_with_llm(cve, solr_checkout, api_key, model, solr_version,
                         max_iterations=25, max_input_tokens=200000):
    """
    Use an agentic LLM to analyze whether a CVE is exploitable in Solr.

    The agent loops using tools to search code. When either the token budget or
    iteration limit is reached, the LLM is forced to conclude with what it has.

    Returns a dict with keys: state, justification, reasoning, affected_jars, llm_analyzed.
    """
    client = anthropic.Anthropic(api_key=api_key)

    user_prompt = LLM_USER_PROMPT_TEMPLATE.format(
        solr_version=solr_version,
        cve_id=cve["cve_id"],
        severity=cve["severity"],
        cvss_score=cve["cvss_score"],
        package=cve["package"],
        version=cve["version"],
        description=cve["description"],
        urls=cve["urls"],
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
            max_tokens=4096,
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
                  f"({iteration} iteration(s))")
            return _parse_llm_response(final_text, cve)

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
        if total_input_tokens >= max_input_tokens:
            return _force_conclusion(
                client, model, messages, cve,
                total_input_tokens, total_output_tokens,
                f"Token budget reached ({total_input_tokens:,} >= {max_input_tokens:,}) "
                f"after {iteration} iterations",
            )
        if iteration >= max_iterations:
            return _force_conclusion(
                client, model, messages, cve,
                total_input_tokens, total_output_tokens,
                f"Iteration limit reached ({iteration} >= {max_iterations})",
            )


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


def _parse_llm_response(text, cve):
    """Parse the LLM's JSON response, with fallback to in_triage."""
    # Try to extract JSON from the response (may have surrounding text)
    json_match = re.search(r"\{[\s\S]*\}", text)
    if json_match:
        try:
            data = json.loads(json_match.group())
            return {
                "state": data.get("state", "in_triage"),
                "justification": data.get("justification", ""),
                "reasoning": data.get("reasoning", text),
                "affected_jars": data.get("affected_jars", []),
                "llm_analyzed": True,
            }
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
    front_matter = {
        "cve": cve["cve_id"],
        "category": ["solr/vex"],
        "versions": solr_version,
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
        "--model", default="balanced",
        choices=["best", "balanced", "fast"],
        help="LLM quality/cost tradeoff: best (Opus, most capable, expensive), "
             "balanced (Sonnet, good tradeoff, default), fast (Haiku, cheapest/fastest)",
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

    # Step 3: Cross-reference with existing VEX and open PRs
    existing_vex = fetch_existing_vex_cves(args.vex_url)
    open_pr_cves = fetch_open_pr_cves(args.solr_site_repo)
    already_covered = existing_vex | open_pr_cves

    new_cves = [c for c in cves if c["cve_id"] not in already_covered]
    # Sort by severity (CRITICAL first) then by CVSS score descending
    _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    new_cves.sort(key=lambda c: (
        _severity_order.get(c["severity"], 9),
        -float(c["cvss_score"]) if c["cvss_score"] != "N/A" else 0,
    ))
    skipped = len(cves) - len(new_cves)
    if skipped:
        print(f"Skipped {skipped} CVE(s) already covered by VEX or open PRs")

    if not new_cves:
        print("All CVEs are already covered. Nothing to do.")
        sys.exit(0)

    print(f"\n=== {len(new_cves)} new CVE(s) to triage ===")
    for c in new_cves:
        print(f"  {c['cve_id']}  {c['severity']}  {c['package']}@{c['version']}")

    # Step 4: Analyze with LLM (unless --skip-llm)
    analyzed = []
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if args.skip_llm:
        print("\nSkipping LLM analysis (--skip-llm)")
        for c in new_cves[:args.max_cves]:
            analyzed.append((c, {
                "state": "in_triage",
                "justification": "",
                "reasoning": "",
                "affected_jars": [],
                "llm_analyzed": False,
            }))
    else:
        if not api_key:
            log.error(
                "ANTHROPIC_API_KEY env var required for LLM analysis.\n"
                "Use --skip-llm to skip, or set the env var."
            )
            sys.exit(1)

        model = MODEL_ALIASES.get(args.model, args.model)
        print(f"Using model: {model}")

        for i, c in enumerate(new_cves[:args.max_cves]):
            print(f"\nAnalyzing [{i+1}/{min(len(new_cves), args.max_cves)}]: {c['cve_id']} ({c['package']})...")
            try:
                analysis = analyze_cve_with_llm(
                    c, solr_checkout, api_key, model, args.solr_version,
                    max_iterations=args.max_iterations,
                    max_input_tokens=args.max_input_tokens,
                )
                analyzed.append((c, analysis))
                print(f"  Result: {analysis['state']}"
                      + (f" ({analysis['justification']})" if analysis.get('justification') else ""))
            except Exception as e:
                log.error("LLM analysis failed for %s: %s", c["cve_id"], e)
                analyzed.append((c, {
                    "state": "in_triage",
                    "justification": "",
                    "reasoning": f"Automated analysis failed: {e}",
                    "affected_jars": [],
                    "llm_analyzed": False,
                }))

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
    print(f"\n=== Summary ===")
    print(f"Image scanned:    {image}")
    print(f"Total app CVEs:   {len(cves)}")
    print(f"Already covered:  {skipped}")
    print(f"New CVEs:         {len(new_cves)}")
    print(f"Analyzed:         {len(analyzed)}")
    for cve, analysis in analyzed:
        print(f"  {cve['cve_id']:20s}  {cve['severity']:8s}  {analysis['state']:15s}  {cve['package']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nReceived Ctrl-C, exiting early")
