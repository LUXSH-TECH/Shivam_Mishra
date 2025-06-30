import csv
import time
import os # Import os for path joining
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException
from webdriver_manager.chrome import ChromeDriverManager

INPUT_CSV_FILENAME = "tga_product_urls.csv"
OUTPUT_CSV_FILENAME = "tga_product_data.csv"
SCREENSHOT_DIR = "error_screenshots" # Directory to save screenshots

# Create screenshot directory if it doesn't exist
if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

# List of fields to extract and their corresponding labels on the page
# !!! DOUBLE CHECK THESE STRINGS AGAINST THE ACTUAL PAGE TEXT USING DEV TOOLS !!!
FIELDS_TO_EXTRACT = [
    "Section 19A approved medicine",
    "Section 19A approval holder",
    "Phone",
    "Approved until",
    "Status",
    "Medicines in short supply/unavailable",
    "Indication(s)",
]

# --- Setup WebDriver ---
options = webdriver.ChromeOptions()
# options.add_argument("--headless")
options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-extensions")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
options.add_argument("--window-size=1920,1080")
options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')

print("Setting up WebDriver...")
try:
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    # Increased main wait time slightly
    wait = WebDriverWait(driver, 25)
    print("WebDriver setup complete.")
except Exception as e:
    print(f"Error setting up WebDriver: {e}")
    exit()

# --- Function to extract data for a specific field ---
def extract_field_data(driver, field_label, current_url):
    """
    Extracts the text content for a specific field based on its label.
    Includes enhanced debugging and waits.
    """
    try:
        # Construct the XPath
        xpath_label = f"//div[contains(@class, 'health-field__label')][normalize-space(.)=\"{field_label}\"]" # Used escaped quotes 
        xpath_item = f"{xpath_label}/following-sibling::div[contains(@class, 'health-field__item')]"

        print(f"  - Searching for label: '{field_label}'")
        
        label_element = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, xpath_label)),
            message=f"Label '{field_label}' not present or text mismatch."
        )

        item_element = driver.find_element(By.XPATH, xpath_item)

        data = item_element.text.strip()
        # Replace multiple spaces/newlines within the text with a single space
        data = ' '.join(data.split())
        print(f"  ✓ Found '{field_label}': '{data[:70]}...'")
        return data

    except TimeoutException as e:
        # This includes cases where the label wasn't found by the wait
        print(f"  ❌ Field '{field_label}' - Timeout or Not Found: {e.msg}")
        # Take screenshot on error
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"error_{field_label.replace(' ', '_').replace('/', '_')}_{timestamp}.png"
        filepath = os.path.join(SCREENSHOT_DIR, filename)
        print(f"the current page url {current_url}")
        try:
            driver.save_screenshot(filepath)
            print(f"    Screenshot saved to: {filepath}")
        except Exception as screen_err:
            print(f"    Failed to save screenshot: {screen_err}")
        return "N/A (Timeout/Not Found)"

    except NoSuchElementException:
        # Should be caught by TimeoutException now, but keep as fallback
        print(f"  ❌ Field '{field_label}' - NoSuchElementException (Label likely found, but item sibling missing?).")
        # Take screenshot on error
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"error_sibling_{field_label.replace(' ', '_').replace('/', '_')}_{timestamp}.png"
        filepath = os.path.join(SCREENSHOT_DIR, filename)
        try:
            driver.save_screenshot(filepath)
            print(f"    Screenshot saved to: {filepath}")
        except Exception as screen_err:
            print(f"    Failed to save screenshot: {screen_err}")
        return "N/A (Sibling Not Found)"

    except Exception as e:
        print(f"  ❌ Error extracting field '{field_label}': {type(e).__name__} - {e}")
        return f"Error: {type(e).__name__}"


all_product_data = []
product_urls = []

# Read URLs from CSV
try:
    with open(INPUT_CSV_FILENAME, "r", newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader) # Skip header row
        # Assuming URL is in the first column (index 0)
        url_column_index = 0
        for row_num, row in enumerate(reader, 1):
            if row and len(row) > url_column_index and row[url_column_index].strip().startswith('http'):
                product_urls.append(row[url_column_index].strip())
            elif row:
                print(f"Skipping invalid row or URL in input CSV (Row {row_num}): {row}")

except FileNotFoundError:
    print(f"Error: Input CSV file not found at '{INPUT_CSV_FILENAME}'")
    if 'driver' in locals() and driver: driver.quit()
    exit()
except Exception as e:
    print(f"Error reading input CSV '{INPUT_CSV_FILENAME}': {e}")
    if 'driver' in locals() and driver: driver.quit()
    exit()

if not product_urls:
    print("No valid URLs found in the input CSV file. Exiting.")
    if 'driver' in locals() and driver: driver.quit()
    exit()

print(f"Found {len(product_urls)} URLs to process from {INPUT_CSV_FILENAME}")

# Add URL column header
output_headers = ["Product Page URL"] + FIELDS_TO_EXTRACT

# --- Process URLs ---
# URLS_TO_PROCESS = product_urls # Process all
URLS_TO_PROCESS = product_urls[:5] # Process only the first 5 (adjust as needed)

print(f"Processing first {len(URLS_TO_PROCESS)} URLs...")

for i, url in enumerate(URLS_TO_PROCESS):
    print(f"\n--- Processing URL {i+1}/{len(URLS_TO_PROCESS)}: {url} ---")
    product_data = {"Product Page URL": url}
    for field_label in FIELDS_TO_EXTRACT:
        product_data[field_label] = "N/A (Not Processed)"

    try:
        driver.get(url)
        # Wait for the main container - increase timeout if pages load very slowly
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".definition-list")))
        print("  Page container '.definition-list' loaded.")
        # Optional: Print a snippet of page source for debugging structure
        # print("Page source snippet:")
        # print(driver.page_source[5000:7000]) # Adjust range as needed
        time.sleep(0.5) # Small pause AFTER container is found, before extracting fields

        # Extract data for each field
        for field_label in FIELDS_TO_EXTRACT:
            # Pass the current URL for potential use in error reporting/screenshots
            data = extract_field_data(driver, field_label, url)
            product_data[field_label] = data

        all_product_data.append(product_data)
        # Increased sleep slightly - uncomment/adjust if needed, but explicit waits are better
        # time.sleep(1.5)

    except TimeoutException:
        print(f"  ❌ Timeout waiting for main page container '.definition-list' on {url}")
        for field_label in FIELDS_TO_EXTRACT:
             product_data[field_label] = "Timeout Error (Page Load)"
        all_product_data.append(product_data)
        # Take screenshot on page load timeout
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"error_pageload_{timestamp}.png"
        filepath = os.path.join(SCREENSHOT_DIR, filename)
        try:
            driver.save_screenshot(filepath)
            print(f"    Screenshot saved to: {filepath}")
        except Exception as screen_err:
            print(f"    Failed to save screenshot: {screen_err}")

    except Exception as e:
        print(f"  ❌ An unexpected error occurred processing {url}: {type(e).__name__} - {e}")
        for field_label in FIELDS_TO_EXTRACT:
             product_data[field_label] = f"Error: {type(e).__name__}"
        all_product_data.append(product_data)

# --- Save to CSV ---
if all_product_data:
    print(f"\nAttempting to save data for {len(all_product_data)} products to {OUTPUT_CSV_FILENAME}...")
    try:
        with open(OUTPUT_CSV_FILENAME, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=output_headers, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(all_product_data)
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