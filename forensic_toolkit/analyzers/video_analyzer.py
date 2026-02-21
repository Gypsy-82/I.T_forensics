"""
Video Analyzer
===============
Deep forensic analysis of video files.
Supports: MP4, MOV, AVI, MKV, WebM, 3GP, WMV

Uses: opencv-python-headless, pymediainfo
"""

import os

from core.hasher import compute_hashes, compute_partial_hashes
from core.file_inspector import (
    get_file_info,
    detect_file_type,
    analyze_mp4_structure,
    detect_appended_data,
    analyze_byte_distribution,
)


def analyze_video(file_path):
    """Perform full forensic analysis on a video file."""
    report = {
        "analysis_type": "Video Forensic Analysis",
        "file_info": {},
        "file_type_detection": {},
        "hashes": {},
        "partial_hashes": {},
        "media_info": {},
        "frame_analysis": {},
        "container_structure": {},
        "appended_data": [],
        "byte_distribution": {},
        "anomalies": [],
    }

    # Basic file info
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

    # MP4/MOV container structure
    detected = report["file_type_detection"]["detected_type"]
    if "MP4" in detected or "MOV" in detected or "Possible" in detected:
        structure = analyze_mp4_structure(file_path)
        report["container_structure"] = structure
        report["anomalies"].extend(structure.get("anomalies", []))

    # MediaInfo analysis
    try:
        from pymediainfo import MediaInfo
        media_info = MediaInfo.parse(file_path)
        tracks = {}
        for track in media_info.tracks:
            track_data = {}
            for attr in [
                "track_type", "format", "format_profile", "codec_id",
                "duration", "bit_rate", "bit_rate_mode",
                "width", "height", "frame_rate", "frame_count",
                "display_aspect_ratio", "rotation",
                "sampling_rate", "channel_s", "bit_depth",
                "encoded_date", "tagged_date", "writing_application",
                "writing_library", "encoder_settings",
                "file_size", "stream_size", "proportion_of_this_stream",
                "color_space", "chroma_subsampling", "scan_type",
                "title", "language",
            ]:
                val = getattr(track, attr, None)
                if val is not None:
                    track_data[attr] = str(val)

            track_key = f"{track.track_type}_{len(tracks)}"
            tracks[track_key] = track_data

        report["media_info"] = tracks

        # Check for multiple video/audio streams (anomaly indicator)
        video_tracks = [k for k in tracks if k.startswith("Video")]
        audio_tracks = [k for k in tracks if k.startswith("Audio")]
        other_tracks = [
            k for k in tracks
            if not k.startswith("Video")
            and not k.startswith("Audio")
            and not k.startswith("General")
        ]

        if len(video_tracks) > 1:
            report["anomalies"].append(
                f"Multiple video streams detected: {len(video_tracks)}"
            )
        if len(audio_tracks) > 1:
            report["anomalies"].append(
                f"Multiple audio streams detected: {len(audio_tracks)}"
            )
        if other_tracks:
            report["anomalies"].append(
                f"Additional streams found: {other_tracks}"
            )

    except ImportError:
        report["media_info"] = {"error": "pymediainfo not available"}
    except Exception as e:
        report["media_info"] = {"error": str(e)}

    # OpenCV frame analysis
    try:
        import cv2
        import numpy as np

        cap = cv2.VideoCapture(file_path)
        if cap.isOpened():
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            codec_int = int(cap.get(cv2.CAP_PROP_FOURCC))
            codec = "".join([chr((codec_int >> 8 * i) & 0xFF) for i in range(4)])

            duration_sec = frame_count / fps if fps > 0 else 0

            report["frame_analysis"] = {
                "frame_count": frame_count,
                "fps": round(fps, 3),
                "width": width,
                "height": height,
                "codec_fourcc": codec,
                "duration_seconds": round(duration_sec, 3),
                "resolution": f"{width}x{height}",
            }

            # Sample frames for analysis (first, middle, last)
            sample_frames = {}
            sample_positions = {
                "first": 0,
                "quarter": frame_count // 4,
                "middle": frame_count // 2,
                "three_quarter": (frame_count * 3) // 4,
                "last": max(0, frame_count - 1),
            }

            for label, pos in sample_positions.items():
                cap.set(cv2.CAP_PROP_POS_FRAMES, pos)
                ret, frame = cap.read()
                if ret:
                    # Compute frame hash for comparison
                    frame_hash = hash(frame.tobytes())
                    mean_intensity = float(np.mean(frame))
                    std_intensity = float(np.std(frame))
                    sample_frames[label] = {
                        "frame_number": pos,
                        "mean_intensity": round(mean_intensity, 2),
                        "std_intensity": round(std_intensity, 2),
                        "is_black_frame": mean_intensity < 5,
                        "shape": list(frame.shape),
                    }

            report["frame_analysis"]["sample_frames"] = sample_frames

            # Check for black frames at start/end (padding indicator)
            if sample_frames.get("first", {}).get("is_black_frame"):
                report["anomalies"].append("First frame is black (possible padding)")
            if sample_frames.get("last", {}).get("is_black_frame"):
                report["anomalies"].append("Last frame is black (possible padding)")

            # Expected file size vs actual (rough estimate)
            if fps > 0 and duration_sec > 0:
                # Very rough: uncompressed would be huge, but we can check
                # if file size is anomalously large for the duration
                mb_per_second = (
                    report["file_info"]["file_size_bytes"] / (1024 * 1024)
                ) / duration_sec
                report["frame_analysis"]["mb_per_second"] = round(mb_per_second, 3)

                if mb_per_second > 50:
                    report["anomalies"].append(
                        f"Unusually high data rate: {mb_per_second:.1f} MB/s "
                        f"- possible embedded/hidden data"
                    )

            cap.release()
        else:
            report["frame_analysis"] = {"error": "Could not open video with OpenCV"}

    except ImportError:
        report["frame_analysis"] = {"error": "opencv-python not available"}
    except Exception as e:
        report["frame_analysis"] = {"error": str(e)}

    return report
