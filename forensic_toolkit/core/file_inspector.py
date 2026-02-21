"""
File Inspector Module
======================
Low-level file analysis: magic bytes, structure, size anomalies,
appended/hidden data detection.
"""

import os
import struct
import mimetypes
import stat
from datetime import datetime


# Common file signatures (magic bytes)
FILE_SIGNATURES = {
    b"\xff\xd8\xff": "JPEG Image",
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"GIF87a": "GIF Image (87a)",
    b"GIF89a": "GIF Image (89a)",
    b"\x42\x4d": "BMP Image",
    b"\x49\x49\x2a\x00": "TIFF Image (Little Endian)",
    b"\x4d\x4d\x00\x2a": "TIFF Image (Big Endian)",
    b"RIFF": "RIFF Container (AVI/WAV/WebP)",
    b"\x1a\x45\xdf\xa3": "Matroska/WebM Video",
    b"\x00\x00\x00": "Possible MP4/MOV/3GP",
    b"\x49\x44\x33": "MP3 (ID3 Tag)",
    b"\xff\xfb": "MP3 Audio",
    b"\xff\xf3": "MP3 Audio",
    b"\xff\xf2": "MP3 Audio",
    b"fLaC": "FLAC Audio",
    b"OggS": "OGG Container",
    b"%PDF": "PDF Document",
    b"PK\x03\x04": "ZIP Archive (DOCX/XLSX/PPTX/ODT)",
    b"\xd0\xcf\x11\xe0": "MS Office Legacy (DOC/XLS/PPT)",
}

# MP4/MOV box types that are standard
MP4_KNOWN_BOXES = {
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide",
    b"pnot", b"moof", b"mfra", b"uuid", b"meta",
}


def get_file_info(file_path):
    """Get basic file system information."""
    stat_info = os.stat(file_path)
    result = {
        "file_name": os.path.basename(file_path),
        "file_path": file_path,
        "file_size_bytes": stat_info.st_size,
        "file_size_human": _human_size(stat_info.st_size),
        "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
        "permissions": stat.filemode(stat_info.st_mode),
    }

    # MIME type detection
    mime, encoding = mimetypes.guess_type(file_path)
    result["mime_type_guessed"] = mime or "unknown"
    result["encoding"] = encoding

    return result


def detect_file_type(file_path):
    """Detect file type by reading magic bytes (file signature)."""
    with open(file_path, "rb") as f:
        header = f.read(32)

    detected = "Unknown"
    for signature, file_type in FILE_SIGNATURES.items():
        if header.startswith(signature):
            detected = file_type
            break

    # Special handling for MP4/MOV - check for ftyp box
    if detected == "Possible MP4/MOV/3GP" or detected == "Unknown":
        if len(header) >= 8:
            box_type = header[4:8]
            if box_type == b"ftyp":
                brand = header[8:12].decode("ascii", errors="replace")
                detected = f"MP4/MOV (brand: {brand})"

    # Check RIFF sub-type
    if detected.startswith("RIFF") and len(header) >= 12:
        sub_type = header[8:12]
        if sub_type == b"AVI ":
            detected = "AVI Video"
        elif sub_type == b"WAVE":
            detected = "WAV Audio"
        elif sub_type == b"WEBP":
            detected = "WebP Image"

    return {
        "detected_type": detected,
        "magic_bytes_hex": header[:16].hex(),
        "magic_bytes_ascii": header[:16].decode("ascii", errors="replace"),
    }


def analyze_mp4_structure(file_path):
    """
    Parse MP4/MOV container structure (boxes/atoms).
    Returns a list of top-level boxes with their sizes.
    Detects unusual padding, unknown boxes, and data anomalies.
    """
    boxes = []
    anomalies = []
    file_size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        offset = 0
        while offset < file_size:
            f.seek(offset)
            header = f.read(8)
            if len(header) < 8:
                if len(header) > 0:
                    anomalies.append(
                        f"Trailing data at offset {offset}: {len(header)} bytes"
                    )
                break

            box_size = struct.unpack(">I", header[:4])[0]
            box_type = header[4:8]

            # Handle extended size (64-bit)
            actual_size = box_size
            if box_size == 1:
                ext_header = f.read(8)
                if len(ext_header) == 8:
                    actual_size = struct.unpack(">Q", ext_header)[0]
                else:
                    anomalies.append(
                        f"Truncated extended box header at offset {offset}"
                    )
                    break
            elif box_size == 0:
                # Box extends to end of file
                actual_size = file_size - offset

            box_type_str = box_type.decode("ascii", errors="replace")

            box_info = {
                "offset": offset,
                "size": actual_size,
                "size_human": _human_size(actual_size),
                "type": box_type_str,
            }

            # Check for unknown box types
            if box_type not in MP4_KNOWN_BOXES:
                box_info["note"] = "Non-standard box type"

            # Check for padding boxes
            if box_type in (b"free", b"skip"):
                box_info["note"] = f"Padding/free space: {_human_size(actual_size)}"
                if actual_size > 1024 * 1024:  # > 1MB of padding
                    anomalies.append(
                        f"Large padding box '{box_type_str}' at offset {offset}: "
                        f"{_human_size(actual_size)}"
                    )

            boxes.append(box_info)

            if actual_size <= 0:
                anomalies.append(f"Invalid box size at offset {offset}")
                break

            offset += actual_size

    # Check if boxes account for the full file
    total_box_size = sum(b["size"] for b in boxes)
    if total_box_size < file_size:
        trailing = file_size - total_box_size
        anomalies.append(
            f"Data beyond last box: {trailing} bytes "
            f"({_human_size(trailing)}) - possible appended data"
        )

    return {
        "boxes": boxes,
        "total_boxes": len(boxes),
        "anomalies": anomalies,
    }


def detect_appended_data(file_path):
    """
    Check for data appended after the logical end of a file.
    Works for: JPEG (FFD9 end marker), PNG (IEND), PDF (%%EOF).
    """
    file_size = os.path.getsize(file_path)
    findings = []

    with open(file_path, "rb") as f:
        header = f.read(16)

        # JPEG: look for FFD9 end marker
        if header[:2] == b"\xff\xd8":
            f.seek(0)
            data = f.read()
            end_marker = data.rfind(b"\xff\xd9")
            if end_marker != -1:
                logical_end = end_marker + 2
                if logical_end < file_size:
                    extra = file_size - logical_end
                    findings.append({
                        "type": "Appended data after JPEG end marker",
                        "logical_end": logical_end,
                        "extra_bytes": extra,
                        "extra_human": _human_size(extra),
                    })

        # PNG: look for IEND chunk
        elif header[:8] == b"\x89PNG\r\n\x1a\n":
            f.seek(0)
            data = f.read()
            iend = data.find(b"IEND")
            if iend != -1:
                # IEND chunk: 4 bytes length + 4 bytes type + 4 bytes CRC
                logical_end = iend + 4 + 4  # after IEND + CRC
                if logical_end < file_size:
                    extra = file_size - logical_end
                    findings.append({
                        "type": "Appended data after PNG IEND chunk",
                        "logical_end": logical_end,
                        "extra_bytes": extra,
                        "extra_human": _human_size(extra),
                    })

        # PDF: look for %%EOF marker
        elif header[:4] == b"%PDF":
            f.seek(max(0, file_size - 1024))
            tail = f.read()
            eof_marker = tail.rfind(b"%%EOF")
            if eof_marker != -1:
                tail_offset = max(0, file_size - 1024)
                logical_end = tail_offset + eof_marker + 5
                if logical_end < file_size:
                    extra = file_size - logical_end
                    # PDF often has a newline after %%EOF
                    if extra > 2:
                        findings.append({
                            "type": "Appended data after PDF %%EOF marker",
                            "logical_end": logical_end,
                            "extra_bytes": extra,
                            "extra_human": _human_size(extra),
                        })

    return findings


def analyze_byte_distribution(file_path, sample_size=65536):
    """
    Analyze the byte frequency distribution of a file.
    High entropy may indicate encryption or compression.
    Uniform distribution may indicate random/encrypted data.
    """
    import math

    with open(file_path, "rb") as f:
        data = f.read(sample_size)

    if not data:
        return {"entropy": 0, "distribution": "empty"}

    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    # Calculate Shannon entropy
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    # Classify
    if entropy > 7.9:
        classification = "High entropy (encrypted/compressed data)"
    elif entropy > 6.0:
        classification = "Medium-high entropy (compressed/binary data)"
    elif entropy > 4.0:
        classification = "Medium entropy (mixed content)"
    elif entropy > 2.0:
        classification = "Low-medium entropy (structured data)"
    else:
        classification = "Low entropy (repetitive/text data)"

    # Find most common and least common bytes
    indexed_freq = [(i, freq[i]) for i in range(256)]
    indexed_freq.sort(key=lambda x: x[1], reverse=True)

    return {
        "entropy": round(entropy, 4),
        "max_entropy": 8.0,
        "classification": classification,
        "sample_size": len(data),
        "top_5_bytes": [
            {"byte": f"0x{b:02x}", "count": c, "percent": round(c / length * 100, 2)}
            for b, c in indexed_freq[:5]
        ],
        "null_byte_count": freq[0],
        "null_byte_percent": round(freq[0] / length * 100, 2),
    }


def _human_size(size_bytes):
    """Convert bytes to human-readable size."""
    if size_bytes < 0:
        return "Invalid"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"
