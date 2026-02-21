"""
Comparison Engine
==================
Compares two or more files to identify anomalies and differences.
Provides deep content-level comparison for video, image, audio, and documents.
"""

import os
import filecmp

from core.hasher import compute_hashes


def compare_files(file_paths, reports):
    """
    Compare multiple analyzed files and identify anomalies.

    Args:
        file_paths: list of sandbox file paths
        reports: list of analysis reports (one per file)

    Returns:
        comparison report dict
    """
    if len(reports) < 2:
        return {"error": "Need at least 2 files to compare"}

    comparison = {
        "comparison_type": "Multi-File Comparison Analysis",
        "file_count": len(reports),
        "files": [],
        "hash_comparison": {},
        "metadata_differences": [],
        "size_analysis": {},
        "content_comparison": {},
        "anomalies": [],
        "verdict": "",
    }

    # File summaries
    for i, report in enumerate(reports):
        comparison["files"].append({
            "index": i + 1,
            "name": report.get("file_info", {}).get("file_name", f"File_{i+1}"),
            "size": report.get("file_info", {}).get("file_size_bytes", 0),
            "size_human": report.get("file_info", {}).get("file_size_human", ""),
            "type": report.get("file_type_detection", {}).get("detected_type", ""),
        })

    # Hash comparison
    _compare_hashes(reports, comparison)

    # Size comparison
    _compare_sizes(reports, comparison)

    # Metadata comparison
    _compare_metadata(reports, comparison)

    # Content-level comparison (type-specific)
    analysis_type = reports[0].get("analysis_type", "")
    if "Video" in analysis_type:
        _compare_video_content(reports, comparison)
    elif "Image" in analysis_type:
        _compare_image_content(file_paths, reports, comparison)
    elif "Audio" in analysis_type:
        _compare_audio_content(reports, comparison)
    elif "Document" in analysis_type:
        _compare_document_content(reports, comparison)

    # Binary comparison
    _binary_diff_summary(file_paths, comparison)

    # Generate verdict
    _generate_verdict(comparison)

    return comparison


def _compare_hashes(reports, comparison):
    """Compare cryptographic hashes across files."""
    hash_data = {}
    for alg in ["md5", "sha256"]:
        values = []
        for r in reports:
            h = r.get("hashes", {}).get(alg, "unknown")
            values.append(h)

        all_match = len(set(values)) == 1
        hash_data[alg] = {
            "values": values,
            "all_match": all_match,
        }

        if not all_match:
            comparison["anomalies"].append(
                f"HASH MISMATCH ({alg.upper()}): Files have different {alg} hashes "
                f"- binary content differs"
            )

    # Partial hashes (head/tail)
    head_hashes = [
        r.get("partial_hashes", {}).get("head_sha256", "") for r in reports
    ]
    tail_hashes = [
        r.get("partial_hashes", {}).get("tail_sha256", "") for r in reports
    ]

    hash_data["head_match"] = len(set(head_hashes)) == 1
    hash_data["tail_match"] = len(set(tail_hashes)) == 1

    if hash_data["head_match"] and not hash_data["tail_match"]:
        comparison["anomalies"].append(
            "Files start identically but differ at the end - "
            "possible appended data on one file"
        )
    elif not hash_data["head_match"] and hash_data["tail_match"]:
        comparison["anomalies"].append(
            "Files differ at the start but end identically - "
            "possible prepended data or different headers"
        )

    comparison["hash_comparison"] = hash_data


def _compare_sizes(reports, comparison):
    """Compare file sizes and detect discrepancies."""
    sizes = [r.get("file_info", {}).get("file_size_bytes", 0) for r in reports]
    names = [r.get("file_info", {}).get("file_name", f"File_{i}") for i, r in enumerate(reports)]

    min_size = min(sizes)
    max_size = max(sizes)
    diff = max_size - min_size

    comparison["size_analysis"] = {
        "sizes": dict(zip(names, sizes)),
        "min_size": min_size,
        "max_size": max_size,
        "difference_bytes": diff,
        "difference_human": _human_size(diff),
        "all_same_size": min_size == max_size,
    }

    if min_size > 0:
        ratio = max_size / min_size
        comparison["size_analysis"]["size_ratio"] = round(ratio, 3)

        if ratio >= 1.8 and ratio <= 2.2:
            comparison["anomalies"].append(
                f"SIZE ANOMALY: Largest file is ~{ratio:.1f}x the smallest "
                f"(difference: {_human_size(diff)}) - "
                f"near-exact doubling detected (common in WhatsApp duplication)"
            )
        elif ratio > 1.1:
            comparison["anomalies"].append(
                f"SIZE DIFFERENCE: Files differ by {_human_size(diff)} "
                f"(ratio: {ratio:.2f}x)"
            )


def _compare_metadata(reports, comparison):
    """Compare metadata fields across files."""
    differences = []

    # Compare media info (for video/audio)
    media_keys_to_compare = [
        "duration", "bit_rate", "width", "height", "frame_rate",
        "frame_count", "codec_id", "format", "sample_rate", "channels",
        "writing_application", "writing_library", "encoded_date",
    ]

    for key in media_keys_to_compare:
        values = []
        for r in reports:
            # Search through all media_info tracks
            media = r.get("media_info", {})
            found = None
            if isinstance(media, dict):
                for track_key, track_data in media.items():
                    if isinstance(track_data, dict) and key in track_data:
                        found = track_data[key]
                        break
            values.append(found)

        # Only report if at least one file has the key
        if any(v is not None for v in values):
            if len(set(str(v) for v in values)) > 1:
                differences.append({
                    "field": key,
                    "values": [
                        {
                            "file": reports[i]["file_info"].get("file_name", f"File_{i}"),
                            "value": str(v) if v else "<not present>",
                        }
                        for i, v in enumerate(values)
                    ],
                })

    # Compare EXIF data (for images)
    exif_keys_all = set()
    for r in reports:
        exif = r.get("exif_data", {})
        if isinstance(exif, dict):
            exif_keys_all.update(exif.keys())

    for key in sorted(exif_keys_all):
        if key in ("note",):
            continue
        values = []
        for r in reports:
            exif = r.get("exif_data", {})
            values.append(exif.get(key, "<not present>"))

        if len(set(str(v) for v in values)) > 1:
            differences.append({
                "field": f"EXIF.{key}",
                "values": [
                    {
                        "file": reports[i]["file_info"].get("file_name", f"File_{i}"),
                        "value": str(v),
                    }
                    for i, v in enumerate(values)
                ],
            })

    if differences:
        comparison["metadata_differences"] = differences
        comparison["anomalies"].append(
            f"METADATA DIFFERENCES: {len(differences)} fields differ between files"
        )
    else:
        comparison["metadata_differences"] = []


def _compare_video_content(reports, comparison):
    """Compare video content using frame analysis data."""
    content = {}

    # Compare frame counts and durations
    durations = []
    frame_counts = []
    resolutions = []

    for r in reports:
        fa = r.get("frame_analysis", {})
        durations.append(fa.get("duration_seconds", 0))
        frame_counts.append(fa.get("frame_count", 0))
        resolutions.append(fa.get("resolution", ""))

    content["durations"] = durations
    content["frame_counts"] = frame_counts
    content["resolutions"] = resolutions

    content["same_duration"] = len(set(durations)) == 1 if durations else False
    content["same_frame_count"] = len(set(frame_counts)) == 1 if frame_counts else False
    content["same_resolution"] = len(set(resolutions)) == 1 if resolutions else False

    # Compare sample frame intensities
    frame_labels = ["first", "quarter", "middle", "three_quarter", "last"]
    frame_matches = 0
    frame_total = 0

    for label in frame_labels:
        intensities = []
        for r in reports:
            sf = r.get("frame_analysis", {}).get("sample_frames", {})
            frame = sf.get(label, {})
            intensities.append(frame.get("mean_intensity", -1))

        if all(i >= 0 for i in intensities):
            frame_total += 1
            # Allow small tolerance for re-encoding
            max_i = max(intensities)
            min_i = min(intensities)
            if max_i > 0 and (max_i - min_i) / max_i < 0.05:
                frame_matches += 1

    if frame_total > 0:
        content["frame_similarity"] = f"{frame_matches}/{frame_total} sample frames match"
        content["content_likely_identical"] = frame_matches == frame_total

        if frame_matches == frame_total:
            comparison["anomalies"].append(
                "VIDEO CONTENT MATCH: Frame analysis suggests identical visual content "
                "despite different file hashes/sizes"
            )

    # Compare container structures
    structures = [r.get("container_structure", {}) for r in reports]
    box_counts = [s.get("total_boxes", 0) for s in structures]
    if len(set(box_counts)) > 1:
        content["different_container_structure"] = True
        comparison["anomalies"].append(
            f"CONTAINER DIFFERENCE: Files have different number of boxes/atoms "
            f"({box_counts})"
        )

    # Check for padding differences
    for i, s in enumerate(structures):
        for box in s.get("boxes", []):
            if box.get("type") in ("free", "skip"):
                padding_size = box.get("size", 0)
                if padding_size > 1024:
                    name = reports[i]["file_info"].get("file_name", f"File_{i}")
                    content.setdefault("padding_found", []).append({
                        "file": name,
                        "padding_type": box["type"],
                        "padding_size": padding_size,
                    })

    comparison["content_comparison"] = content


def _compare_image_content(file_paths, reports, comparison):
    """Compare image content at the pixel level."""
    content = {}

    # Compare dimensions
    dims = []
    for r in reports:
        ip = r.get("image_properties", {})
        dims.append(f"{ip.get('width', '?')}x{ip.get('height', '?')}")

    content["dimensions"] = dims
    content["same_dimensions"] = len(set(dims)) == 1

    # Compare pixel statistics
    pixel_stats = [r.get("pixel_analysis", {}) for r in reports]
    if all("mean_rgb" in ps for ps in pixel_stats):
        rgb_similar = True
        for channel in ["red", "green", "blue"]:
            values = [ps["mean_rgb"][channel] for ps in pixel_stats]
            if max(values) - min(values) > 2.0:
                rgb_similar = False
                break

        content["pixel_statistics_match"] = rgb_similar

        if rgb_similar and not comparison["hash_comparison"].get("sha256", {}).get("all_match", True):
            comparison["anomalies"].append(
                "IMAGE CONTENT MATCH: Pixel statistics are nearly identical "
                "despite different file hashes - likely same image re-encoded"
            )

    # Deep pixel comparison using OpenCV
    if len(file_paths) == 2 and content.get("same_dimensions"):
        try:
            import cv2
            import numpy as np

            img1 = cv2.imread(file_paths[0])
            img2 = cv2.imread(file_paths[1])

            if img1 is not None and img2 is not None:
                if img1.shape == img2.shape:
                    diff = cv2.absdiff(img1, img2)
                    mean_diff = float(np.mean(diff))
                    max_diff = int(np.max(diff))
                    identical_pixels = int(np.sum(np.all(diff == 0, axis=2)))
                    total_pixels = img1.shape[0] * img1.shape[1]

                    content["pixel_comparison"] = {
                        "mean_pixel_difference": round(mean_diff, 4),
                        "max_pixel_difference": max_diff,
                        "identical_pixels": identical_pixels,
                        "total_pixels": total_pixels,
                        "identical_percent": round(
                            identical_pixels / total_pixels * 100, 2
                        ),
                        "are_pixel_identical": mean_diff == 0,
                    }

                    if mean_diff == 0:
                        comparison["anomalies"].append(
                            "PIXEL-PERFECT MATCH: Images are pixel-identical "
                            "but have different file hashes - container/metadata differs"
                        )
                    elif mean_diff < 1.0:
                        comparison["anomalies"].append(
                            f"NEAR-IDENTICAL: Mean pixel difference is only {mean_diff:.4f} "
                            f"- likely same image with minor re-encoding artifacts"
                        )

        except ImportError:
            content["pixel_comparison"] = {"note": "OpenCV not available for deep comparison"}
        except Exception as e:
            content["pixel_comparison"] = {"error": str(e)}

    comparison["content_comparison"] = content


def _compare_audio_content(reports, comparison):
    """Compare audio content using waveform and metadata."""
    content = {}

    # Compare durations
    durations = []
    bitrates = []
    sample_rates = []

    for r in reports:
        ap = r.get("audio_properties", {})
        durations.append(ap.get("duration_seconds", 0))
        bitrates.append(ap.get("bitrate", 0))
        sample_rates.append(ap.get("sample_rate", 0))

    content["durations"] = durations
    content["bitrates"] = bitrates
    content["sample_rates"] = sample_rates

    content["same_duration"] = (
        len(set(round(d, 1) for d in durations)) == 1 if durations else False
    )
    content["same_bitrate"] = len(set(bitrates)) == 1 if bitrates else False

    if content["same_duration"] and not content["same_bitrate"]:
        comparison["anomalies"].append(
            "AUDIO CONTENT: Same duration but different bitrates - "
            "likely same audio re-encoded at different quality"
        )

    # Compare waveform analysis
    waveforms = [r.get("waveform_analysis", {}) for r in reports]
    if all("rms_level" in w for w in waveforms):
        rms_values = [w["rms_level"] for w in waveforms]
        if max(rms_values) > 0:
            rms_ratio = min(rms_values) / max(rms_values)
            content["rms_similarity"] = round(rms_ratio, 4)
            if rms_ratio > 0.95:
                content["waveform_likely_identical"] = True

    comparison["content_comparison"] = content


def _compare_document_content(reports, comparison):
    """Compare document content and structure."""
    content = {}

    # Compare page/paragraph counts
    for key in ["page_count", "paragraph_count", "word_count", "total_characters"]:
        values = []
        for r in reports:
            dp = r.get("document_properties", {})
            sa = r.get("structure_analysis", {})
            val = dp.get(key) or sa.get(key)
            values.append(val)

        if any(v is not None for v in values):
            content[key] = values
            if len(set(str(v) for v in values)) > 1:
                comparison["anomalies"].append(
                    f"DOCUMENT DIFFERENCE: '{key}' differs: {values}"
                )

    comparison["content_comparison"] = content


def _binary_diff_summary(file_paths, comparison):
    """Quick binary comparison between files."""
    if len(file_paths) == 2:
        identical = filecmp.cmp(file_paths[0], file_paths[1], shallow=False)
        comparison["binary_identical"] = identical

        if identical:
            comparison["anomalies"].append(
                "FILES ARE BINARY IDENTICAL - they are exact copies"
            )
    elif len(file_paths) > 2:
        pairs = []
        for i in range(len(file_paths)):
            for j in range(i + 1, len(file_paths)):
                identical = filecmp.cmp(file_paths[i], file_paths[j], shallow=False)
                pairs.append({
                    "file_a": os.path.basename(file_paths[i]),
                    "file_b": os.path.basename(file_paths[j]),
                    "binary_identical": identical,
                })
        comparison["binary_pairs"] = pairs


def _generate_verdict(comparison):
    """Generate a human-readable verdict based on all findings."""
    anomalies = comparison.get("anomalies", [])

    if not anomalies:
        comparison["verdict"] = (
            "NO ANOMALIES DETECTED: Files appear consistent and normal."
        )
        return

    # Classify the situation
    has_hash_mismatch = any("HASH MISMATCH" in a for a in anomalies)
    has_content_match = any("CONTENT MATCH" in a for a in anomalies)
    has_size_anomaly = any("SIZE" in a for a in anomalies)
    has_binary_identical = any("BINARY IDENTICAL" in a for a in anomalies)
    has_pixel_match = any("PIXEL" in a for a in anomalies)

    if has_binary_identical:
        comparison["verdict"] = (
            "EXACT DUPLICATE: Files are binary identical copies. "
            "Same content, same encoding, same metadata."
        )
    elif has_content_match and has_hash_mismatch and has_size_anomaly:
        comparison["verdict"] = (
            "RE-ENCODED DUPLICATE WITH SIZE ANOMALY: Files contain the same "
            "content but differ in encoding/container structure. One file is "
            "significantly larger, suggesting re-encoding added padding, "
            "extra streams, or modified container metadata. This is consistent "
            "with WhatsApp duplication behavior."
        )
    elif has_content_match and has_hash_mismatch:
        comparison["verdict"] = (
            "RE-ENCODED DUPLICATE: Files contain the same content but have "
            "been encoded differently. The container format, metadata, or "
            "encoding parameters differ."
        )
    elif has_pixel_match and has_hash_mismatch:
        comparison["verdict"] = (
            "VISUAL DUPLICATE: Images are visually identical at the pixel level "
            "but the file encoding differs. Likely re-saved or re-encoded."
        )
    elif has_hash_mismatch:
        comparison["verdict"] = (
            f"FILES DIFFER: {len(anomalies)} anomalies detected. "
            "See detailed anomaly list for specifics."
        )
    else:
        comparison["verdict"] = (
            f"ANOMALIES FOUND: {len(anomalies)} issues detected. "
            "Review the detailed findings."
        )


def _human_size(size_bytes):
    """Convert bytes to human-readable size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"
