import json
import os
import uuid

from questions import scope_files


def generate_scope_files():
    """
    Split all_questions.json into chunks of 25 questions and save them as separate files.
    Each file will be named with a UUID and contain 25 questions.
    """
    # Get the question directory, default to 'question'
    scope_directory = os.environ.get('SCOPE_DIR', 'scope')
    os.makedirs(scope_directory, exist_ok=True)

    # Create the question directory if it doesn't exist
    os.makedirs(scope_directory, exist_ok=True)

    try:
        # Load all questions

        # Split into chunks of 25
        chunk_size = 25
        total_questions = len(scope_files)

        for i in range(0, total_questions, chunk_size):
            # Get a chunk of 25 questions
            chunk = scope_files[i:i + chunk_size]

            # Generate a unique filename
            filename = f"{str(uuid.uuid4())}.json".replace("-", "")
            filepath = os.path.join(scope_directory, filename)

            # Save the chunk to a new file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(chunk, f, indent=2, ensure_ascii=False)

            print(f"Saved {len(chunk)} questions to {filepath}")

        print(
            f"\nSuccessfully split {total_questions} questions into {((total_questions - 1) // chunk_size) + 1} files")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def main():
    generate_scope_files()


if __name__ == '__main__':
    main()
