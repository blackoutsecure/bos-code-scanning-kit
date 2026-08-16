"""Ecosystem auto-detector.

Walks a repository root and reports which ecosystems are present so the
scanner orchestrator can decide which tools to run. Pure stdlib —
single tree walk; no network; no subprocess.

The detector classifies repos along three orthogonal axes:

    languages          Programming languages with non-trivial source files.
    package_managers   Manifests / lockfiles indicating a dependency graph.
    artifact_types     Build artefacts that drive specific scanners
                       (Dockerfile -> hadolint+trivy image, IaC -> checkov,
                        GH workflows -> actionlint, shell scripts -> shellcheck).

The output is consumed by `cli` and the composite Action to
emit one "scanner plan" — the list of tool invocations to perform.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Knobs — patterns and ignored directories
# ---------------------------------------------------------------------------

IGNORE_DIRS: frozenset[str] = frozenset({
    ".git",
    ".github-private",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "coverage",
    "htmlcov",
    "__pycache__",
})

# Language signal files. A repo "has" a language if AT LEAST one source
# file with that extension exists, OR a marker manifest is present.
LANG_EXT: dict[str, tuple[str, ...]] = {
    "python":     (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "go":         (".go",),
    "java":       (".java",),
    "kotlin":     (".kt", ".kts"),
    "csharp":     (".cs",),
    "ruby":       (".rb",),
    "rust":       (".rs",),
    "shell":      (".sh", ".bash", ".bats"),
    "c":          (".c", ".h"),
    "cpp":        (".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"),
    "swift":      (".swift",),
}

LANG_MARKERS: dict[str, tuple[str, ...]] = {
    "python":     ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "poetry.lock"),
    "javascript": ("package.json",),
    "typescript": ("tsconfig.json",),
    "go":         ("go.mod",),
    "java":       ("pom.xml", "build.gradle", "build.gradle.kts"),
    "csharp":     ("*.csproj", "*.sln"),
    "ruby":       ("Gemfile",),
    "rust":       ("Cargo.toml",),
}

# Artefact-type signal files.
ARTIFACT_PATTERNS: dict[str, tuple[str, ...]] = {
    "dockerfile": ("Dockerfile", "Dockerfile.*", "*.dockerfile"),
    "compose":    ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    "github_workflows": (".github/workflows/*.yml", ".github/workflows/*.yaml"),
    "terraform":  ("*.tf", "*.tf.json"),
    "kubernetes": ("k8s/*.yml", "k8s/*.yaml", "kubernetes/*.yml", "kubernetes/*.yaml"),
    "shell":      ("*.sh", "*.bash"),
    "helm":       ("Chart.yaml",),
}

# Package-manager signal files.
PACKAGE_MANAGER_FILES: dict[str, tuple[str, ...]] = {
    "pip":         ("requirements.txt", "requirements-*.txt"),
    "pyproject":   ("pyproject.toml",),
    "poetry":      ("poetry.lock",),
    "npm":         ("package-lock.json",),
    "yarn":        ("yarn.lock",),
    "pnpm":        ("pnpm-lock.yaml",),
    "go_modules":  ("go.sum",),
    "maven":       ("pom.xml",),
    "gradle":      ("build.gradle", "build.gradle.kts"),
    "cargo":       ("Cargo.lock",),
    "bundler":     ("Gemfile.lock",),
    "nuget":       ("packages.lock.json",),
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Detection:
    languages: tuple[str, ...] = ()
    artifact_types: tuple[str, ...] = ()
    package_managers: tuple[str, ...] = ()
    files_scanned: int = 0

    def codeql_languages(self) -> tuple[str, ...]:
        """Map detected languages → CodeQL language identifiers."""
        codeql_map = {
            "python":     "python",
            "javascript": "javascript-typescript",
            "typescript": "javascript-typescript",
            "go":         "go",
            "java":       "java-kotlin",
            "kotlin":     "java-kotlin",
            "csharp":     "csharp",
            "ruby":       "ruby",
            "rust":       "rust",
            "c":          "c-cpp",
            "cpp":        "c-cpp",
            "swift":      "swift",
        }
        seen: list[str] = []
        for lang in self.languages:
            mapped = codeql_map.get(lang)
            if mapped and mapped not in seen:
                seen.append(mapped)
        return tuple(seen)

    def quality_applicability(self) -> dict[str, dict[str, object]]:
        """Describe whether the shared quality gates apply to this tree."""
        node_signals = sorted(
            {
                *(
                    language
                    for language in self.languages
                    if language in {"javascript", "typescript"}
                ),
                *(manager for manager in self.package_managers if manager in {"npm", "yarn", "pnpm"}),
            }
        )
        python_signals = sorted(
            {
                *({"python"} if "python" in self.languages else set()),
                *(manager for manager in self.package_managers if manager in {"pip", "pyproject", "poetry"}),
            }
        )
        shell_signals = sorted(
            {"shell"}
            if "shell" in self.languages or "shell" in self.artifact_types
            else set()
        )

        def result(signals: list[str], label: str) -> dict[str, object]:
            if signals:
                return {
                    "applicable": True,
                    "signals": signals,
                    "reason": f"{label} signals detected: {', '.join(signals)}.",
                }
            return {
                "applicable": False,
                "signals": [],
                "reason": f"No {label} source or package metadata detected.",
            }

        return {
            "node": result(node_signals, "Node"),
            "python": result(python_signals, "Python"),
            "shell": result(shell_signals, "Shell"),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "languages": list(self.languages),
            "artifact_types": list(self.artifact_types),
            "package_managers": list(self.package_managers),
            "files_scanned": self.files_scanned,
            "quality_applicability": self.quality_applicability(),
        }


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------

def detect(root: Path) -> Detection:
    """Return a `Detection` describing the ecosystems present under `root`."""
    if not root.is_dir():
        return Detection()

    langs: set[str] = set()
    artifacts: set[str] = set()
    pms: set[str] = set()
    files_count = 0

    # Build reverse-lookup maps for fast extension/name matching.
    ext_to_lang: dict[str, str] = {}
    for lang, exts in LANG_EXT.items():
        for ext in exts:
            ext_to_lang[ext] = lang

    pm_basenames: dict[str, str] = {}
    pm_prefixes: list[tuple[str, str]] = []   # (basename_prefix, pm) for glob-like
    for pm, names in PACKAGE_MANAGER_FILES.items():
        for n in names:
            if "*" in n:
                # crude prefix match for `requirements-*.txt`
                prefix, suffix = n.split("*", 1)
                pm_prefixes.append((prefix, pm))
            else:
                pm_basenames[n] = pm

    for dirpath, dirnames, filenames in _walk(root):
        rel = dirpath.relative_to(root)
        rel_posix = rel.as_posix()

        for fname in filenames:
            files_count += 1

            # Language signal — extension OR marker
            ext = _ext(fname)
            if ext in ext_to_lang:
                langs.add(ext_to_lang[ext])

            for lang, markers in LANG_MARKERS.items():
                for marker in markers:
                    if _name_matches(fname, marker):
                        langs.add(lang)
                        break

            # Package managers
            if fname in pm_basenames:
                pms.add(pm_basenames[fname])
            for prefix, pm in pm_prefixes:
                if fname.startswith(prefix) and fname.endswith(".txt"):
                    pms.add(pm)

            # Artefact types — Dockerfile family
            if fname == "Dockerfile" or fname.startswith("Dockerfile.") or fname.endswith(".dockerfile"):
                artifacts.add("dockerfile")
            if fname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                artifacts.add("compose")
            if fname == "Chart.yaml":
                artifacts.add("helm")
            if ext == ".tf" or fname.endswith(".tf.json"):
                artifacts.add("terraform")
            if ext in (".sh", ".bash"):
                artifacts.add("shell")

            # GitHub workflows (path-dependent)
            if rel_posix == ".github/workflows" and (fname.endswith(".yml") or fname.endswith(".yaml")):
                artifacts.add("github_workflows")

            # k8s manifests (dir-based heuristic)
            top = rel.parts[0] if rel.parts else ""
            if top in ("k8s", "kubernetes") and (fname.endswith(".yml") or fname.endswith(".yaml")):
                artifacts.add("kubernetes")

        # Prune ignored dirs in-place for os.walk-style iteration
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

    return Detection(
        languages=tuple(sorted(langs)),
        artifact_types=tuple(sorted(artifacts)),
        package_managers=tuple(sorted(pms)),
        files_scanned=files_count,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _walk(root: Path):
    """`os.walk`-style generator yielding (Path, [dirnames], [filenames]).

    Implemented with `Path.iterdir` so callers can mutate `dirnames`
    in place to skip subtrees.
    """
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        dirnames: list[str] = []
        filenames: list[str] = []
        for entry in entries:
            if entry.is_symlink():
                # Skip symlinks to avoid loops; symlinked source rarely matters here.
                continue
            if entry.is_dir():
                dirnames.append(entry.name)
            elif entry.is_file():
                filenames.append(entry.name)
        yield current, dirnames, filenames
        for d in dirnames:
            stack.append(current / d)


def _ext(name: str) -> str:
    dot = name.rfind(".")
    return name[dot:] if dot >= 0 else ""


def _name_matches(name: str, pattern: str) -> bool:
    if "*" not in pattern:
        return name == pattern
    # Very simple glob: leading/trailing `*` only.
    if pattern.startswith("*"):
        return name.endswith(pattern[1:])
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    prefix, suffix = pattern.split("*", 1)
    return name.startswith(prefix) and name.endswith(suffix)
