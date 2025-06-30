import csv
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException
from webdriver_manager.chrome import ChromeDriverManager

INPUT_CSV_FILENAME = "tga_product_urls.csv"
OUTPUT_CSV_FILENAME = "tga_product_data.csv"

# List of fields to extract and their corresponding labels on the page
FIELDS_TO_EXTRACT = [
    "Section 19A approved medicine",
    "Section 19A approval holder",
    "Phone",
    "Approved until",
    "Status",
    "Medicines in short supply/unavailable",
    "Indication(s)",
    # Add "Related medicines shortage notifications" if you also want that link/text
    # "Related medicines shortage notifications"
]

# --- Setup WebDriver ---
options = webdriver.ChromeOptions()
# options.add_argument("--headless") # Optional: Run in headless mode
options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-extensions")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
options.add_argument("--window-size=1920,1080") # May help with element visibility
options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36') # Mimic a common user agent


print("Setting up WebDriver...")
try:
    # Use webdriver-manager to handle driver download/path automatically
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    wait = WebDriverWait(driver, 20) # Slightly shorter wait, adjust if needed
    print("WebDriver setup complete.")
except Exception as e:
    print(f"Error setting up WebDriver: {e}")
    exit()

# --- Function to extract data for a specific field ---
def extract_field_data(driver, field_label):
    """
    Extracts the text content for a specific field based on its label.
    Uses contains() for class matching and normalize-space() for text matching.
    Returns the text or "N/A" if the field is not found.
    """
    try:
        # Corrected XPath:
        # 1. Find a div that contains the class 'health-field__label'.
        # 2. Check if its normalized text content equals the field_label.
        # 3. Find the following sibling div that contains the class 'health-field__item'.
        xpath = (
            f"//div[contains(@class, 'health-field__label')][normalize-space(.)=\"{field_label}\"]" # could not find it first > corrected with quotes
            f"/following-sibling::div[contains(@class, 'health-field__item')]"
        )
        # Wait briefly for the specific element to be present (optional but can help stability)
        element = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.XPATH, xpath))
        )
        # Getting text - .text gets text from all descendant elements too
        data = element.text.strip()
        # Replace multiple spaces/newlines within the text with a single space for cleaner output
        data = ' '.join(data.split())
        print(f"  ✓ Found '{field_label}': '{data[:70]}...'") # Print confirmation and snippet
        return data
    except TimeoutException:
        print(f"  - Field '{field_label}' not found (Timeout waiting for element).")
        return "N/A (Timeout)"
    except NoSuchElementException:
        # This might be redundant if TimeoutException catches it first, but good fallback
        print(f"  - Field '{field_label}' not found (NoSuchElement).")
        return "N/A"
    except Exception as e:
        print(f"  - Error extracting field '{field_label}': {e}")
        return f"Error: {type(e).__name__}"


all_product_data = []
product_urls = []

# Read URLs from CSV
try:
    with open(INPUT_CSV_FILENAME, "r", newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader) # Read header row
        print(f"Input CSV header: {header}")
        url_column_index = 0 # Assuming URL is in the first column (index 0)
        # Optional: find URL column by header name if needed
        # try:
        #     url_column_index = header.index('URL_Column_Name') # Replace with actual name if applicable
        # except ValueError:
        #     print(f"Error: URL column not found in header: {header}")
        #     driver.quit()
        #     exit()

        for row in reader:
            if row and len(row) > url_column_index and row[url_column_index].strip().startswith('http'): # Ensure row has data and looks like a URL
                product_urls.append(row[url_column_index].strip())
            elif row:
                print(f"Skipping invalid row or URL in input CSV: {row}")

except FileNotFoundError:
    print(f"Error: Input CSV file not found at '{INPUT_CSV_FILENAME}'")
    driver.quit()
    exit()
except Exception as e:
    print(f"Error reading input CSV '{INPUT_CSV_FILENAME}': {e}")
    driver.quit()
    exit()

if not product_urls:
    print("No valid URLs found in the input CSV file. Exiting.")
    driver.quit()
    exit()

print(f"Found {len(product_urls)} URLs to process from {INPUT_CSV_FILENAME}")

# Add URL column header
output_headers = ["Product Page URL"] + FIELDS_TO_EXTRACT

# --- Process URLs ---

# Decide how many URLs to process (e.g., first 5 for testing, or all)
URLS_TO_PROCESS = product_urls # Process all
# URLS_TO_PROCESS = product_urls[:5] # Process only the first 5

print(f"Processing {len(URLS_TO_PROCESS)} URLs...")

for i, url in enumerate(URLS_TO_PROCESS):
    print(f"\n--- Processing URL {i+1}/{len(URLS_TO_PROCESS)}: {url} ---")
    product_data = {"Product Page URL": url} # Store data in a dictionary

    # Initialize data with N/A to ensure all columns exist even on error
    for field_label in FIELDS_TO_EXTRACT:
        product_data[field_label] = "N/A (Not Processed)"

    try:
        driver.get(url)
        # Wait for the main container of the fields to be present
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".definition-list")))
        print("  Page loaded successfully.")

        # Extract data for each field
        for field_label in FIELDS_TO_EXTRACT:
            data = extract_field_data(driver, field_label)
            product_data[field_label] = data

        all_product_data.append(product_data)
        time.sleep(1) # Small delay between requests

    except TimeoutException:
        print(f"Timeout waiting for page content structure on {url}")
        # Update dictionary with timeout error for all fields for this URL
        for field_label in FIELDS_TO_EXTRACT:
             product_data[field_label] = "Timeout Error (Page Load)"
        all_product_data.append(product_data) # Still add the row with errors

    except Exception as e:
        print(f"An unexpected error occurred processing {url}: {e}")
        # Update dictionary with general error for all fields for this URL
        for field_label in FIELDS_TO_EXTRACT:
             product_data[field_label] = f"Error: {type(e).__name__}"
        all_product_data.append(product_data) # Still add the row with errors

# --- Save to CSV ---
if all_product_data:
    print(f"\nAttempting to save data for {len(all_product_data)} products to {OUTPUT_CSV_FILENAME}...")
    try:
        with open(OUTPUT_CSV_FILENAME, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=output_headers, extrasaction='ignore') # ignore fields not in header
            writer.writeheader()
            writer.writerows(all_product_data) # Use writerows for list of dicts
        print(f"\n✅ Done. Extracted data for {len(all_product_data)} products.")
        print(f"📁 Saved data to: {OUTPUT_CSV_FILENAME}")
    except Exception as e:
        print(f"\n❌ Error writing to output CSV file '{OUTPUT_CSV_FILENAME}': {e}")
else:
    print("\nNo data was successfully extracted to save.")

# --- Cleanup ---
print("Closing WebDriver...")
driver.quit()
print("Script finished.")