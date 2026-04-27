# depthwatch

> A CLI tool that monitors Python dependency trees for version drift and security advisories across multiple projects.

---

## Installation

```bash
pip install depthwatch
```

Or with [pipx](https://pypa.github.io/pipx/) for isolated installs:

```bash
pipx install depthwatch
```

---

## Usage

Run a scan against one or more projects by pointing depthwatch at a `requirements.txt` or `pyproject.toml`:

```bash
# Scan a single project
depthwatch scan ./my-project

# Scan multiple projects and output a summary report
depthwatch scan ./api ./worker ./frontend --report summary

# Check for security advisories only
depthwatch scan ./my-project --advisories-only

# Watch for drift continuously (checks every 24h)
depthwatch watch ./my-project --interval 24h
```

### Example Output

```
Project: my-project
────────────────────────────────────────
  requests        2.28.0  →  2.31.0   [OUTDATED]
  urllib3         1.26.5  →  2.0.7    [OUTDATED] ⚠ CVE-2023-43804
  flask           2.3.2       ✔ up to date

2 outdated packages, 1 security advisory found.
```

---

## Configuration

depthwatch can be configured via a `.depthwatch.toml` file in your project root:

```toml
[scan]
ignore = ["pytest", "black"]
fail_on_advisory = true
```

---

## License

[MIT](LICENSE)