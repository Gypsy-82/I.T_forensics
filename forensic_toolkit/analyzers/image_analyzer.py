"""
Image Analyzer
===============
Deep forensic analysis of image files.
Supports: JPEG, PNG, GIF, BMP, TIFF, WebP

Uses: Pillow (PIL), numpy
"""

import os

from core.hasher import compute_hashes, compute_partial_hashes
from core.file_inspector import (
    get_file_info,
    detect_file_type,
    detect_appended_data,
    analyze_byte_distribution,
)


def analyze_image(file_path):
    """Perform full forensic analysis on an image file."""
    report = {
        "analysis_type": "Image Forensic Analysis",
        "file_info": {},
        "file_type_detection": {},
        "hashes": {},
        "partial_hashes": {},
        "image_properties": {},
        "exif_data": {},
        "pixel_analysis": {},
        "appended_data": [],
        "byte_distribution": {},
        "anomalies": [],
    }

    # Basic analysis
    report["file_info"] = get_file_info(file_path)
    report["file_type_detection"] = detect_file_type(file_path)
    report["hashes"] = compute_hashes(file_path)
    report["partial_hashes"] = compute_partial_hashes(file_path)
    report["byte_distribution"] = analyze_byte_distribution(file_path)
    report["appended_data"] = detect_appended_data(file_path)

    if report["appended_data"]:
        for item in report["appended_data"]:
            report["anomalies"].append(
                f"APPENDED DATA: {item['type']} - {item['extra_human']} extra"
            )

    # Check if detected type matches extension
    detected = report["file_type_detection"]["detected_type"]
    ext = os.path.splitext(file_path)[1].lower()
    _check_extension_mismatch(detected, ext, report)

    # Pillow analysis
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        img = Image.open(file_path)

        report["image_properties"] = {
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "resolution": f"{img.width}x{img.height}",
            "total_pixels": img.width * img.height,
            "is_animated": getattr(img, "is_animated", False),
            "n_frames": getattr(img, "n_frames", 1),
            "info_keys": list(img.info.keys()),
        }

        # DPI info
        dpi = img.info.get("dpi")
        if dpi:
            report["image_properties"]["dpi"] = dpi

        # JPEG quality estimation
        if img.format == "JPEG":
            quant = img.quantization
            if quant:
                # Average quantization value - lower means higher quality
                avg_quant = sum(sum(t) for t in quant.values()) / sum(
                    len(t) for t in quant.values()
                )
                report["image_properties"]["avg_quantization"] = round(avg_quant, 2)
                if avg_quant < 3:
                    report["image_properties"]["estimated_quality"] = "Very High (95+)"
                elif avg_quant < 6:
                    report["image_properties"]["estimated_quality"] = "High (85-95)"
                elif avg_quant < 15:
                    report["image_properties"]["estimated_quality"] = "Medium (60-85)"
                else:
                    report["image_properties"]["estimated_quality"] = "Low (<60)"

        # EXIF data extraction
        exif_data = {}
        raw_exif = img.getexif()
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag_name = TAGS.get(tag_id, f"Unknown_Tag_{tag_id}")
                try:
                    if isinstance(value, bytes):
                        exif_data[tag_name] = value.hex()
                    else:
                        exif_data[tag_name] = str(value)
                except Exception:
                    exif_data[tag_name] = "<unreadable>"

            # GPS data
            gps_info = {}
            for tag_id, value in raw_exif.get_ifd(0x8825).items():
                tag_name = GPSTAGS.get(tag_id, f"GPS_Tag_{tag_id}")
                try:
                    gps_info[tag_name] = str(value)
                except Exception:
                    gps_info[tag_name] = "<unreadable>"

            if gps_info:
                exif_data["GPS_Data"] = gps_info
                report["anomalies"].append(
                    "GPS/Location data found in EXIF metadata"
                )

        report["exif_data"] = exif_data if exif_data else {"note": "No EXIF data found"}

        # Pixel-level analysis
        try:
            import numpy as np

            img_array = np.array(img.convert("RGB"))

            report["pixel_analysis"] = {
                "mean_rgb": {
                    "red": round(float(np.mean(img_array[:, :, 0])), 2),
                    "green": round(float(np.mean(img_array[:, :, 1])), 2),
                    "blue": round(float(np.mean(img_array[:, :, 2])), 2),
                },
                "std_rgb": {
                    "red": round(float(np.std(img_array[:, :, 0])), 2),
                    "green": round(float(np.std(img_array[:, :, 1])), 2),
                    "blue": round(float(np.std(img_array[:, :, 2])), 2),
                },
                "is_uniform": bool(np.std(img_array) < 1.0),
                "unique_colors_sample": _count_unique_colors(img_array),
            }

            # Check for solid color images (suspicious)
            if report["pixel_analysis"]["is_uniform"]:
                report["anomalies"].append(
                    "Image appears to be a single solid color"
                )

        except ImportError:
            report["pixel_analysis"] = {"error": "numpy not available"}

        # Compression ratio analysis
        raw_size = img.width * img.height * len(img.getbands())
        actual_size = report["file_info"]["file_size_bytes"]
        if raw_size > 0:
            compression_ratio = actual_size / raw_size
            report["image_properties"]["compression_ratio"] = round(
                compression_ratio, 4
            )
            report["image_properties"]["raw_uncompressed_size_estimate"] = raw_size

            if compression_ratio > 1.0:
                report["anomalies"].append(
                    f"File is larger than uncompressed pixel data would suggest "
                    f"(ratio: {compression_ratio:.2f}) - possible embedded data"
                )

        img.close()

    except ImportError:
        report["image_properties"] = {"error": "Pillow not available"}
    except Exception as e:
        report["image_properties"]["error"] = str(e)

    return report


def _count_unique_colors(img_array, max_sample=10000):
    """Count approximate unique colors from a sample of pixels."""
    import numpy as np

    h, w, c = img_array.shape
    total = h * w
    if total > max_sample:
        indices = np.random.choice(total, max_sample, replace=False)
        flat = img_array.reshape(-1, c)
        sample = flat[indices]
    else:
        sample = img_array.reshape(-1, c)

    unique = np.unique(sample, axis=0)
    return {
        "sampled_pixels": len(sample),
        "unique_colors_in_sample": len(unique),
    }


def _check_extension_mismatch(detected_type, extension, report):
    """Check if the file extension matches the detected type."""
    extension_map = {
        ".jpg": ["JPEG"],
        ".jpeg": ["JPEG"],
        ".png": ["PNG"],
        ".gif": ["GIF"],
        ".bmp": ["BMP"],
        ".tiff": ["TIFF"],
        ".tif": ["TIFF"],
        ".webp": ["WebP"],
    }

    expected_types = extension_map.get(extension, [])
    if expected_types:
        match = any(t.lower() in detected_type.lower() for t in expected_types)
        if not match:
            report["anomalies"].append(
                f"Extension mismatch: file has '{extension}' extension "
                f"but detected as '{detected_type}'"
            )
