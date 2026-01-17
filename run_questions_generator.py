from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
from questions_generator import GenerateQuestions
from questions import questions_generator


def load_processed_questions():
    """Load processed questions from both collections and reversed_collections JSON files"""
    processed = set()

    for filename in ["questions.json"]:
        if not os.path.exists(filename):
            continue
        try:
            with open(filename, "r") as f:
                data = json.load(f)
                processed.update(item.get("question", "") for item in data)
        except Exception as e:
            print(f"Error loading {filename}: {e}")

    return processed




def main():
    try:
        processed = load_processed_questions()
        total = len(questions_generator)
        skipped = 0
        processed_count = 0

        print(f"Total questions: {total}")
        print(f"Already processed: {len(processed)}")

        counter = 0
        for i, question in enumerate(questions_generator):
            # Skip if already processed
            if question in processed:
                skipped += 1
                print(f"[{i + 1}/{total}] Skipping (already processed): {question[:50]}...")
                continue

            print(f"[{i + 1}/{total}] Processing: {question[:50]}...")
            bot = GenerateQuestions(teardown=True)
            bot.ask_question(question)
            processed_count += 1

            counter += 1
            if counter >= 25:
                break

        print(f"\n=== Summary ===")
        print(f"Skipped: {skipped}")
        print(f"Newly processed: {processed_count}")
        print(f"Total: {total}")

    except Exception as e:
        print(f"Error: {e}")




if __name__ == '__main__':
    main()

