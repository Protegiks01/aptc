import json
import os
import time
import uuid

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from questions import BASE_URL, question_generator
import pyperclip
import re
from typing import List


class GenerateQuestions:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        self.options.add_argument("--headless")
        self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.collections_url = []
        super(GenerateQuestions, self).__init__()

    def __enter__(self):
        self.driver.get(BASE_URL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.teardown:
            self.driver.quit()

    def toggle_deep_research(self):
        wait = WebDriverWait(self.driver, 20)

        xpath = '//button[.//span[normalize-space(text())="Fast"]]'
        btn = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
        btn.click()

        xpath_primary = "//div[@role='menuitem' and .//span[normalize-space(text())='Deep Research']]"
        menu_item = wait.until(EC.element_to_be_clickable((By.XPATH, xpath_primary)))
        menu_item.click()

    def ask_question(self, question_gotten):
        wait = WebDriverWait(self.driver, 1200)

        try:
            self.driver.get(BASE_URL)

            # # wait for the form containing the textarea
            form = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
            )

            # find the textarea inside the form
            textarea = form.find_element(By.CSS_SELECTOR, 'textarea')
            self.toggle_deep_research()

            # type the question
            textarea.click()
            textarea.clear()
            formatted_question = question_generator(question_gotten)

            # Use JavaScript to set the textarea value directly. It's more reliable for large text.
            self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
            # Dispatch an 'input' event to make sure the web application detects the change.
            self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                       textarea)
            textarea.send_keys(".. ")

            textarea.send_keys(Keys.ENTER)

            time.sleep(10)
            current_url = self.driver.current_url

            # add the current url to collections
            self.save_to_questions(question_gotten, current_url)
        except Exception as a:
            print(f"There was an error in index : {a}")

            # In your Deepwiki class where you save to questions.json

    def save_to_questions(self, question_gotten, url):
        """Save question and URL to questions.json"""
        collections_file = "questions.json"

        # Load existing data or start fresh
        try:
            if os.path.exists(collections_file):
                with open(collections_file, "r") as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
            else:
                data = []
        except json.JSONDecodeError:
            print("Invalid questions.json, creating new file")
            data = []

        # Add new entry
        data.append({
            "question": question_gotten,
            "url": url,
            "questions_generated": False
        })

        # Save with proper formatting
        try:
            with open(collections_file, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving to collections: {e}")


class GetQuestions:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        # self.options.add_argument("--headless")
        # self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.collections_url = []
        super(GetQuestions, self).__init__()

    def get_questions(self, url):

        try:
            self.driver.get(url)

            wait = WebDriverWait(self.driver, 120)
            #  this would click the copy button
            copy_button_selector = (By.CSS_SELECTOR, '[aria-label="Copy"]')
            all_copy_buttons = wait.until(
                EC.presence_of_all_elements_located(copy_button_selector)
            )
            last_copy_button = all_copy_buttons[-1]
            wait.until(EC.element_to_be_clickable(last_copy_button)).click()

            xpath = "//div[@role='menuitem' and normalize-space(text())='Copy response']"
            el = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
            el.click()

            clipboard_content = pyperclip.paste()

            questions = self.get_question_content(clipboard_content)

            # Load existing data or start fresh
            try:
                if os.path.exists("all_questions.json"):
                    with open("all_questions.json", "r") as f:
                        content = f.read().strip()
                        data = json.loads(content) if content else []
                else:
                    data = []
            except json.JSONDecodeError:
                print("Invalid questions.json, creating new file")
                data = []

            data.extend(questions)
            # Save with proper formatting
            try:
                with open("all_questions.json", "w") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Error saving to collections: {e}")

            # Clear textarea for next question
            self.mark_questions_generated(url)
            time.sleep(1)  # give it a moment to clear
        except Exception as e:
            print(f"There was an error in index {url}: {e}")

    def get_question_content(self, clip_board_content: str) -> List[str]:
        """
            Extracts security audit questions from the provided text using regex.
            """
        pattern = r'"(\[File:.*?)"'
        questions = re.findall(pattern, clip_board_content, flags=re.DOTALL)
        # Optional: Clean up whitespace (strip) for each question found
        return [q.strip() for q in questions]

    def mark_questions_generated(self, url):
        """Mark this URL's report as generated in questions.json"""
        if not url:
            return

        try:
            with open("questions.json", "r") as f:
                data = json.load(f)

            # Find and update the item
            for item in data:
                if item.get("url") == url:
                    item["questions_generated"] = True
                    break

            with open("questions.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error marking report as generated: {e}")



def split_all_questions():
    """
    Split all_questions.json into chunks of 25 questions and save them as separate files.
    Each file will be named with a UUID and contain 25 questions.
    """
    # Get the question directory, default to 'question'
    question_directory = os.environ.get('QUESTION_DIR', 'question')
    input_file = 'all_questions.json'

    # Create the question directory if it doesn't exist
    os.makedirs(question_directory, exist_ok=True)

    try:
        # Load all questions
        with open(input_file, 'r', encoding='utf-8') as f:
            all_questions = json.load(f)

        # Split into chunks of 25
        chunk_size = 25
        total_questions = len(all_questions)

        for i in range(0, total_questions, chunk_size):
            # Get a chunk of 25 questions
            chunk = all_questions[i:i + chunk_size]

            # Generate a unique filename
            filename = f"{str(uuid.uuid4())}.json".replace("-","")
            filepath = os.path.join(question_directory, filename)

            # Save the chunk to a new file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(chunk, f, indent=2, ensure_ascii=False)

            print(f"Saved {len(chunk)} questions to {filepath}")

        print(f"\nSuccessfully split {total_questions} questions into {((total_questions-1)//chunk_size) + 1} files")

    except FileNotFoundError:
        print(f"Error: {input_file} not found")
    except json.JSONDecodeError:
        print(f"Error: {input_file} is not a valid JSON file")
    except Exception as e:
        print(f"An error occurred: {str(e)}")