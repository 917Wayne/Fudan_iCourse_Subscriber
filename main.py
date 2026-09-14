"""iCourse Subscriber — main orchestration.

Runs a single check: login → detect new lectures → stream audio → transcribe
→ summarize → email. Designed to be triggered by GitHub Actions cron.
"""

import time
import traceback
from datetime import datetime, timedelta

from src import config
from src.database import Database
from src.emailer import Emailer
from src.icourse import ICourseClient
from src.summarizer import Summarizer
from src.transcriber import IncompleteAudioError, NoAudioStreamError, Transcriber
from src.webvpn import WebVPNSession


def process_lecture(
    client: ICourseClient,
    db: Database,
    transcriber: Transcriber,
    summarizer: Summarizer,
    course_id: str,
    course_title: str,
    lecture: dict,
) -> str | None:
    """Download, transcribe, and summarize a single lecture."""
    sub_id = str(lecture["sub_id"])
    sub_title = lecture.get("sub_title", sub_id)
    date = lecture.get("date", "")

    print(f"\n  -- Processing: {sub_title} ({date})")
    print(f"    [Time] Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    t_start = time.time()

    existing = db.get_lecture(sub_id)
    has_transcript = existing and existing.get("transcript")
    has_summary = existing and existing.get("summary")

    # 1) Transcribe
    if has_transcript:
        print(f"    Transcript exists ({len(existing['transcript'])} chars), skipping transcription.")
        transcript = existing["transcript"]
    else:
        print(f"    [Time] Fetching video URL at {time.strftime('%H:%M:%S')}")
        video_url = client.get_video_url(course_id, sub_id)
        if not video_url:
            print(f"    No video URL for {sub_id}, skipping.")
            return None

        vpn_url, http_headers = client.get_stream_params(video_url)
        print(f"    [Time] Streaming audio at {time.strftime('%H:%M:%S')}")
        print(f"    [URL] {vpn_url[:100]}...")

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                transcript = transcriber.transcribe_url(
                    vpn_url, http_headers=http_headers,
                )
                db.update_transcript(sub_id, transcript)
                break
            except IncompleteAudioError as e:
                print(f"    [WARN] Attempt {attempt}/{max_attempts}: {e}")
                if attempt < max_attempts:
                    client = _check_session(client)
                    video_url = client.get_video_url(course_id, sub_id)
                    vpn_url, http_headers = client.get_stream_params(video_url)
                    print(f"    Retrying with fresh connection...")
                else:
                    print(f"    [FAIL] All {max_attempts} attempts got incomplete audio, using best result.")
                    transcript = transcriber._last_transcript
                    db.update_transcript(sub_id, transcript)
            except NoAudioStreamError as e:
                print(f"    [SKIP] Video-only (no audio stream): {e}")
                db.update_error(sub_id, "transcribe", str(e))
                db.mark_processed(sub_id)
                return None
            except Exception as e:
                print(f"    [FAIL] Transcription error: {type(e).__name__}: {e}")
                db.update_error(sub_id, "transcribe", str(e))
                raise

    # 2) Summarize
    if not transcript.strip():
        print(f"    Empty transcript, skipping summary.")
        db.mark_processed(sub_id)
        db.clear_error(sub_id)
        return None

    if has_summary:
        print(f"    Summary exists ({len(existing['summary'])} chars), skipping summarization.")
        summary = existing["summary"]
    else:
        try:
            print(f"    [Time] Generating summary at {time.strftime('%H:%M:%S')}")
            print(f"    Transcript length: {len(transcript)} chars")
            summary, model_used = summarizer.summarize(course_title, transcript)
            print(f"    [OK] Summary by {model_used}: {len(summary)} chars")
            db.update_summary_with_model(sub_id, summary, model_used)
        except Exception as e:
            print(f"    [FAIL] Summarization error: {type(e).__name__}: {e}")
            db.update_error(sub_id, "summarize", str(e))
            raise

    db.mark_processed(sub_id)
    db.clear_error(sub_id)
    elapsed = time.time() - t_start
    print(f"    [Time] Done at {time.strftime('%H:%M:%S')}: {sub_title} (total {elapsed:.0f}s)")
    return summary


def login_with_retry(max_attempts: int = 5) -> WebVPNSession:
    """Login to WebVPN + iCourse CAS with retry (new session each attempt)."""
    for attempt in range(max_attempts):
        try:
            vpn = WebVPNSession()
            print(f"\n[Login] WebVPN (attempt {attempt + 1}/{max_attempts})...")
            vpn.login()
            print("[Login] iCourse CAS...")
            vpn.authenticate_icourse()
            return vpn
        except Exception as e:
            if attempt < max_attempts - 1:
                print(f"  Failed: {type(e).__name__}, retrying...")
                time.sleep(3)
            else:
                raise


def _check_session(client: ICourseClient) -> ICourseClient:
    """Verify WebVPN session; re-login if expired. Returns (possibly new) client."""
    if client.check_alive():
        return client
    print("[Session] WebVPN session expired, re-logging in...")
    vpn = login_with_retry()
    return ICourseClient(vpn)


def run():
    """Single execution of the full pipeline."""
    print("=" * 60)
    print("iCourse Subscriber — starting run")
    print("=" * 60)

    # 动态滑动窗口：仅处理前 3 天内的新课，彻底过滤旧学期积压
    cutoff_date = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d")
    print(f"[*] 动态日期过滤：只处理 {cutoff_date} 及之后的课程")

    if not config.COURSE_IDS:
        print("No COURSE_IDS configured. Set the COURSE_IDS env var.")
        return

    db = Database()
    transcriber = Transcriber()
    summarizer = Summarizer()
    emailer = Emailer() if config.SMTP_EMAIL and config.SMTP_PASSWORD else None

    vpn = login_with_retry()
    client = ICourseClient(vpn)

    for course_id in config.COURSE_IDS:
        try:
            print(f"\n{'─' * 50}")
            print(f"[Course] {course_id}")

            client = _check_session(client)
            detail = client.get_course_detail(course_id)
            course_title = detail["title"]
            teacher = detail["teacher"]
            lectures = detail["lectures"]
            playback_count = sum(1 for l in lectures if l.get("has_playback"))
            print(f"  Title: {course_title} (Teacher: {teacher})")
            print(f"  Total lectures: {len(lectures)} ({playback_count} with playback)")

            db.upsert_course(course_id, course_title, teacher)

            known_processed = db.get_processed_sub_ids(course_id)
            new_lectures = []
            for lec in lectures:
                if lec.get("has_playback") and str(lec["sub_id"]) not in known_processed:
                    lec_date = lec.get("date", "")
                    # 仅保留最近 3 天内的课
                    if lec_date and lec_date < cutoff_date:
                        continue
                    new_lectures.append(lec)

            # 去重
            seen_titles = set()
            deduped = []
            for lec in new_lectures:
                title = lec.get("sub_title", "")
                if title in seen_titles:
                    print(f"  [Dedup] Skipping duplicate: {title} (sub_id={lec['sub_id']})")
                    continue
                seen_titles.add(title)
                deduped.append(lec)
            new_lectures = deduped

            print(f"  New lectures to process: {len(new_lectures)}")

            if not new_lectures:
                print("  No new lectures in window, skipping.")
                continue

            for lecture in new_lectures:
                sub_id = str(lecture["sub_id"])
                db.insert_lecture(
                    sub_id, course_id,
                    lecture.get("sub_title", ""),
                    lecture.get("date", ""),
                )
                client = _check_session(client)
                try:
                    summary = process_lecture(
                        client, db, transcriber, summarizer,
                        course_id, course_title, lecture,
                    )
                    # 优化：单课单发，生成一个总结立即投递一封邮件，绝不堆积
                    if summary and emailer:
                        single_item = [{
                            "sub_id": sub_id,
                            "course_title": course_title,
                            "sub_title": lecture.get("sub_title", sub_id),
                            "date": lecture.get("date", ""),
                            "summary": summary,
                        }]
                        print(f"\n[Email] Sending summary for lecture {sub_id}...")
                        if emailer.send(single_item):
                            db.mark_emailed_batch([sub_id])
                            print(f"[Email] Successfully delivered to mailbox.")
                        else:
                            print(f"[Email] Send failed for {sub_id}, will retry next cycle.")
                except Exception:
                    print(f"    ERROR processing {sub_id}:")
                    traceback.print_exc()

        except Exception:
            print(f"  ERROR processing course {course_id}:")
            traceback.print_exc()

    print(f"\n{'=' * 60}")
    print("Run complete.")


if __name__ == "__main__":
    run()
