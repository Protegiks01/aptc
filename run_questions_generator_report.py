from pathlib import Path
import sys

from questions_generator import GetQuestions

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os


def get_pending_urls():
    """Get list of URLs that need reports"""
    if not os.path.exists("questions.json"):
        print("No questions.json found")
        return []

    try:
        with open("questions.json", "r") as f:
            data = json.load(f)

        pending = []

        for item in data:
            url = item.get("url", "")
            pending.append(url)

        return pending
    except Exception as e:
        print(f"Error loading collections: {e}")
        return []


def main():
    try:
        pending_urls = get_pending_urls()
        total = len(pending_urls)

        if total == 0:
            print("No pending reports to generate")
        else:
            print(f"Found {total} URLs needing reports")

            counter = 0
            report = GetQuestions(teardown=True)
            for i, url in enumerate(pending_urls):
                print(f"[{i + 1}/{total}] Generating report for: {url[:50]}...")
                report.get_questions(url)
                counter += 1
                if counter >= 500:
                    break

            print(f"\n=== Completed {total} reports ===")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()
