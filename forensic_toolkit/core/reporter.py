"""
Report Generator
=================
Generates forensic analysis reports.

Rules:
- Reports are ONLY saved to the user's Desktop
- ONLY when the user explicitly agrees via prompt
- No hidden files, no logs, no artifacts anywhere else
- If user declines, results are displayed on screen only
"""

import os
import json
from datetime import datetime


def get_desktop_path():
    """Get the user's Desktop path (cross-platform)."""
    home = os.path.expanduser("~")

    # Linux/Mac
    desktop = os.path.join(home, "Desktop")
    if os.path.isdir(desktop):
        return desktop

    # Fallback: XDG Desktop
    xdg_desktop = os.environ.get("XDG_DESKTOP_DIR")
    if xdg_desktop and os.path.isdir(xdg_desktop):
        return xdg_desktop

    # Last resort: home directory
    return home


def display_report(report, is_comparison=False):
    """Display the report on screen in a readable format."""
    print("\n")
    print("=" * 70)

    if is_comparison:
        print("  FORENSIC COMPARISON REPORT")
    else:
        print(f"  FORENSIC ANALYSIS REPORT - {report.get('analysis_type', 'Unknown')}")

    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    if is_comparison:
        _display_comparison_report(report)
    else:
        _display_single_report(report)

    print("=" * 70)
    print()


def _display_single_report(report):
    """Display a single-file analysis report."""
    # File Info
    _section("FILE INFORMATION")
    fi = report.get("file_info", {})
    for key, val in fi.items():
        print(f"  {key:25s}: {val}")

    # File Type Detection
    _section("FILE TYPE DETECTION")
    ft = report.get("file_type_detection", {})
    for key, val in ft.items():
        print(f"  {key:25s}: {val}")

    # Hashes
    _section("CRYPTOGRAPHIC HASHES")
    hashes = report.get("hashes", {})
    for alg, val in hashes.items():
        print(f"  {alg.upper():25s}: {val}")

    # Partial Hashes
    ph = report.get("partial_hashes", {})
    if ph:
        print()
        for key, val in ph.items():
            print(f"  {key:25s}: {val}")

    # Media/Document Properties
    props_key = None
    for k in ["media_info", "audio_properties", "image_properties", "document_properties"]:
        if k in report and report[k]:
            props_key = k
            break

    if props_key:
        _section(props_key.upper().replace("_", " "))
        _print_nested(report[props_key], indent=2)

    # EXIF Data
    if "exif_data" in report and report["exif_data"]:
        _section("EXIF / METADATA")
        _print_nested(report["exif_data"], indent=2)

    # Frame Analysis
    if "frame_analysis" in report and report["frame_analysis"]:
        _section("FRAME ANALYSIS")
        _print_nested(report["frame_analysis"], indent=2)

    # Container Structure
    if "container_structure" in report:
        cs = report["container_structure"]
        if cs.get("boxes"):
            _section("CONTAINER STRUCTURE")
            print(f"  Total boxes/atoms: {cs.get('total_boxes', 0)}")
            for box in cs["boxes"]:
                note = f" [{box['note']}]" if "note" in box else ""
                print(
                    f"  Offset {box['offset']:>10d} | "
                    f"{box['type']:>6s} | "
                    f"{box['size_human']:>12s}{note}"
                )

    # Waveform Analysis
    if "waveform_analysis" in report and report["waveform_analysis"]:
        _section("WAVEFORM ANALYSIS")
        _print_nested(report["waveform_analysis"], indent=2)

    # Pixel Analysis
    if "pixel_analysis" in report and report["pixel_analysis"]:
        _section("PIXEL ANALYSIS")
        _print_nested(report["pixel_analysis"], indent=2)

    # Structure Analysis
    if "structure_analysis" in report and report["structure_analysis"]:
        _section("STRUCTURE ANALYSIS")
        _print_nested(report["structure_analysis"], indent=2, max_depth=3)

    # Byte Distribution
    if "byte_distribution" in report:
        _section("BYTE DISTRIBUTION / ENTROPY")
        _print_nested(report["byte_distribution"], indent=2)

    # Appended Data
    if report.get("appended_data"):
        _section("APPENDED / HIDDEN DATA")
        for item in report["appended_data"]:
            _print_nested(item, indent=2)

    # Anomalies
    _section("ANOMALIES DETECTED")
    anomalies = report.get("anomalies", [])
    if anomalies:
        for i, a in enumerate(anomalies, 1):
            print(f"  [{i}] {a}")
    else:
        print("  None detected.")


def _display_comparison_report(report):
    """Display a comparison report."""
    # Files compared
    _section("FILES COMPARED")
    for f in report.get("files", []):
        print(
            f"  [{f['index']}] {f['name']} "
            f"({f['size_human']}) - {f['type']}"
        )

    # Hash Comparison
    _section("HASH COMPARISON")
    hc = report.get("hash_comparison", {})
    for alg, data in hc.items():
        if isinstance(data, dict) and "all_match" in data:
            status = "MATCH" if data["all_match"] else "MISMATCH"
            print(f"  {alg.upper():12s}: {status}")
            if not data["all_match"]:
                for i, v in enumerate(data.get("values", [])):
                    print(f"    File {i+1}: {v}")

    # Size Analysis
    _section("SIZE ANALYSIS")
    sa = report.get("size_analysis", {})
    for key, val in sa.items():
        if key != "sizes":
            print(f"  {key:25s}: {val}")
    if "sizes" in sa:
        print()
        for name, size in sa["sizes"].items():
            print(f"    {name}: {size:,} bytes")

    # Metadata Differences
    diffs = report.get("metadata_differences", [])
    if diffs:
        _section("METADATA DIFFERENCES")
        for diff in diffs:
            print(f"  Field: {diff['field']}")
            for v in diff["values"]:
                print(f"    {v['file']}: {v['value']}")
            print()

    # Content Comparison
    cc = report.get("content_comparison", {})
    if cc:
        _section("CONTENT COMPARISON")
        _print_nested(cc, indent=2, max_depth=3)

    # Binary Comparison
    if "binary_identical" in report:
        _section("BINARY COMPARISON")
        print(f"  Binary identical: {report['binary_identical']}")
    if "binary_pairs" in report:
        _section("BINARY PAIR COMPARISON")
        for pair in report["binary_pairs"]:
            print(
                f"  {pair['file_a']} vs {pair['file_b']}: "
                f"{'IDENTICAL' if pair['binary_identical'] else 'DIFFERENT'}"
            )

    # Anomalies
    _section("ANOMALIES DETECTED")
    anomalies = report.get("anomalies", [])
    if anomalies:
        for i, a in enumerate(anomalies, 1):
            print(f"  [{i}] {a}")
    else:
        print("  None detected.")

    # Verdict
    _section("VERDICT")
    print(f"  {report.get('verdict', 'No verdict generated.')}")


def prompt_save_report(report, is_comparison=False):
    """
    Ask the user if they want to save the report to Desktop.
    ONLY saves if user explicitly agrees.
    """
    print()
    response = input(
        "Would you like to save this report to your Desktop? (y/n): "
    ).strip().lower()

    if response != "y":
        print("[*] Report not saved. No files were written to disk.")
        return None

    desktop = get_desktop_path()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if is_comparison:
        filename = f"forensic_comparison_{timestamp}.json"
    else:
        file_name = report.get("file_info", {}).get("file_name", "unknown")
        safe_name = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in file_name
        )
        filename = f"forensic_{safe_name}_{timestamp}.json"

    save_path = os.path.join(desktop, filename)

    # Add generation metadata
    save_data = {
        "generated_at": datetime.now().isoformat(),
        "tool": "Forensic Toolkit v1.0",
        "report": report,
    }

    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(save_data, f, indent=2, default=str)

    print(f"[+] Report saved to: {save_path}")
    return save_path


def _section(title):
    """Print a section header."""
    print()
    print(f"  --- {title} ---")
    print()


def _print_nested(data, indent=2, max_depth=5, _depth=0):
    """Recursively print nested dict/list structures."""
    if _depth >= max_depth:
        print(" " * indent + str(data)[:200])
        return

    prefix = " " * indent

    if isinstance(data, dict):
        for key, val in data.items():
            if isinstance(val, (dict, list)):
                print(f"{prefix}{key}:")
                _print_nested(val, indent + 4, max_depth, _depth + 1)
            else:
                print(f"{prefix}{str(key):25s}: {val}")
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                print(f"{prefix}[{i}]:")
                _print_nested(item, indent + 4, max_depth, _depth + 1)
            else:
                print(f"{prefix}  - {item}")
    else:
        print(f"{prefix}{data}")
