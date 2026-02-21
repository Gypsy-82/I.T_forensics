"""
User Interface Module
======================
Prompt-driven interface for the Forensic Toolkit.
Guides the user step-by-step through the analysis process.
"""

import os
import sys
import mimetypes

from core.sandbox import Sandbox
from core.reporter import display_report, prompt_save_report
from core.comparator import compare_files
from analyzers.video_analyzer import analyze_video
from analyzers.image_analyzer import analyze_image
from analyzers.audio_analyzer import analyze_audio
from analyzers.document_analyzer import analyze_document


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                  FORENSIC TOOLKIT v1.0                      ║
║          File Anomaly & Forensic Analysis Tool              ║
║                                                             ║
║  Sandboxed | Offline | No Data Leaves This Machine          ║
╚══════════════════════════════════════════════════════════════╝
"""

FILE_CATEGORIES = {
    "video": {
        "extensions": {
            ".mp4", ".mov", ".avi", ".mkv", ".webm",
            ".wmv", ".flv", ".3gp", ".m4v", ".ts",
        },
        "analyzer": analyze_video,
        "label": "Video",
    },
    "image": {
        "extensions": {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".tiff", ".tif", ".webp", ".ico", ".svg",
        },
        "analyzer": analyze_image,
        "label": "Image",
    },
    "audio": {
        "extensions": {
            ".mp3", ".wav", ".flac", ".ogg", ".aac",
            ".wma", ".m4a", ".opus", ".aiff",
        },
        "analyzer": analyze_audio,
        "label": "Audio",
    },
    "document": {
        "extensions": {
            ".pdf", ".docx", ".doc", ".xlsx", ".xls",
            ".pptx", ".ppt", ".odt", ".ods", ".odp",
            ".txt", ".csv", ".json", ".xml", ".html",
            ".rtf", ".log",
        },
        "analyzer": analyze_document,
        "label": "Document",
    },
}


def run_toolkit():
    """Main entry point for the forensic toolkit."""
    print(BANNER)

    while True:
        mode = _prompt_mode()
        if mode == "quit":
            print("\n[*] Exiting Forensic Toolkit. Goodbye.")
            break

        if mode == "single":
            _run_single_analysis()
        elif mode == "compare":
            _run_comparison_analysis()

        print()
        again = input("Run another analysis? (y/n): ").strip().lower()
        if again != "y":
            print("\n[*] Exiting Forensic Toolkit. Goodbye.")
            break


def _prompt_mode():
    """Prompt user to select analysis mode."""
    print("\nSelect analysis mode:")
    print("  [1] Single File Analysis   - Full forensic breakdown of one file")
    print("  [2] Comparison Analysis    - Anomaly detection between 2+ files")
    print("  [q] Quit")
    print()

    while True:
        choice = input("Enter choice (1/2/q): ").strip().lower()
        if choice in ("1", "single"):
            return "single"
        elif choice in ("2", "compare", "comparison"):
            return "compare"
        elif choice in ("q", "quit", "exit"):
            return "quit"
        else:
            print("  Invalid choice. Please enter 1, 2, or q.")


def _prompt_file_path(prompt_text="Enter file path: "):
    """Prompt user for a valid file path."""
    while True:
        path = input(prompt_text).strip()

        # Remove quotes if user wrapped the path
        if (path.startswith('"') and path.endswith('"')) or \
           (path.startswith("'") and path.endswith("'")):
            path = path[1:-1]

        # Expand user home directory
        path = os.path.expanduser(path)

        if not os.path.exists(path):
            print(f"  File not found: {path}")
            print("  Please enter a valid file path.")
            continue

        if not os.path.isfile(path):
            print(f"  Not a file: {path}")
            continue

        return os.path.abspath(path)


def _detect_category(file_path):
    """Auto-detect the file category based on extension."""
    ext = os.path.splitext(file_path)[1].lower()

    for category, info in FILE_CATEGORIES.items():
        if ext in info["extensions"]:
            return category

    return None


def _prompt_category(file_path):
    """Ask user to select or confirm file category."""
    detected = _detect_category(file_path)

    if detected:
        label = FILE_CATEGORIES[detected]["label"]
        print(f"\n  Auto-detected file type: {label}")
        confirm = input(f"  Use {label} analyzer? (y/n): ").strip().lower()
        if confirm == "y" or confirm == "":
            return detected

    print("\n  Select file type:")
    print("    [1] Video   (MP4, MOV, AVI, MKV, WebM, etc.)")
    print("    [2] Image   (JPEG, PNG, GIF, BMP, TIFF, WebP, etc.)")
    print("    [3] Audio   (MP3, WAV, FLAC, OGG, AAC, etc.)")
    print("    [4] Document (PDF, DOCX, XLSX, TXT, CSV, etc.)")
    print()

    while True:
        choice = input("  Enter choice (1-4): ").strip()
        category_map = {"1": "video", "2": "image", "3": "audio", "4": "document"}
        if choice in category_map:
            return category_map[choice]
        print("    Invalid choice. Please enter 1, 2, 3, or 4.")


def _run_single_analysis():
    """Execute single-file forensic analysis."""
    print("\n--- Single File Analysis ---\n")

    file_path = _prompt_file_path("Enter file path: ")
    category = _prompt_category(file_path)
    analyzer = FILE_CATEGORIES[category]["analyzer"]

    print(f"\n[*] Starting {FILE_CATEGORIES[category]['label']} forensic analysis...")
    print("[*] Creating sandbox environment...")

    with Sandbox() as sandbox:
        # Import file into sandbox
        sandbox_path = sandbox.import_file(file_path)
        print(f"[+] File imported to sandbox (read-only copy)")
        print("[*] Analyzing...\n")

        # Run analysis
        report = analyzer(sandbox_path)

        # Replace sandbox paths with original paths in report
        report["file_info"]["original_path"] = file_path
        report["file_info"]["file_path"] = file_path

        # Display report
        display_report(report, is_comparison=False)

        # Prompt to save
        prompt_save_report(report, is_comparison=False)

    print("[+] Sandbox cleaned up. No artifacts remain.")


def _run_comparison_analysis():
    """Execute multi-file comparison analysis."""
    print("\n--- Comparison Analysis ---\n")
    print("Enter file paths (minimum 2 files).")
    print("Type 'done' when finished adding files.\n")

    file_paths = []
    while True:
        prompt = f"File {len(file_paths) + 1} path (or 'done'): "
        path_input = input(prompt).strip().lower()

        if path_input in ("done", "d") and len(file_paths) >= 2:
            break
        elif path_input in ("done", "d"):
            print("  Need at least 2 files. Please add more.")
            continue

        path = _prompt_file_path(f"File {len(file_paths) + 1} path: ") \
            if path_input in ("done", "d") \
            else None

        if path is None:
            # Re-prompt properly
            raw = path_input
            # Remove quotes
            if (raw.startswith('"') and raw.endswith('"')) or \
               (raw.startswith("'") and raw.endswith("'")):
                raw = raw[1:-1]
            raw = os.path.expanduser(raw)

            if not os.path.exists(raw):
                print(f"  File not found: {raw}")
                continue
            if not os.path.isfile(raw):
                print(f"  Not a file: {raw}")
                continue
            path = os.path.abspath(raw)

        file_paths.append(path)
        print(f"  [+] Added: {os.path.basename(path)}")

    # Detect category from first file
    category = _prompt_category(file_paths[0])
    analyzer = FILE_CATEGORIES[category]["analyzer"]

    print(f"\n[*] Starting {FILE_CATEGORIES[category]['label']} comparison analysis...")
    print(f"[*] Comparing {len(file_paths)} files...")
    print("[*] Creating sandbox environment...")

    with Sandbox() as sandbox:
        # Import all files into sandbox
        sandbox_paths = []
        for fp in file_paths:
            sp = sandbox.import_file(fp)
            sandbox_paths.append(sp)
            print(f"  [+] Imported: {os.path.basename(fp)}")

        print("[*] Analyzing files...\n")

        # Analyze each file
        reports = []
        for i, sp in enumerate(sandbox_paths):
            print(f"  Analyzing file {i + 1}/{len(sandbox_paths)}...")
            report = analyzer(sp)
            report["file_info"]["original_path"] = file_paths[i]
            report["file_info"]["file_path"] = file_paths[i]
            reports.append(report)

        # Run comparison
        print("  Running comparison analysis...")
        comparison = compare_files(sandbox_paths, reports)

        # Display individual reports
        for i, report in enumerate(reports):
            print(f"\n{'=' * 70}")
            print(f"  FILE {i + 1} OF {len(reports)}")
            display_report(report, is_comparison=False)

        # Display comparison report
        display_report(comparison, is_comparison=True)

        # Prompt to save
        save_choice = input(
            "\nSave reports to Desktop? (a=all, c=comparison only, n=none): "
        ).strip().lower()

        if save_choice == "a":
            for report in reports:
                prompt_save_report(report, is_comparison=False)
            prompt_save_report(comparison, is_comparison=True)
        elif save_choice == "c":
            prompt_save_report(comparison, is_comparison=True)
        else:
            print("[*] Reports not saved. No files were written to disk.")

    print("[+] Sandbox cleaned up. No artifacts remain.")
