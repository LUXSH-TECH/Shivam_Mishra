import csv
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementClickInterceptedException
from webdriver_manager.chrome import ChromeDriverManager

# =============== USER INPUT HERE ===============
max_pages = 0  # 0 for all the pages and non-zero values to limit the no of pages.
# ===============================================

# Setup WebDriver
options = webdriver.ChromeOptions()
# options.add_argument("--headless")
options.add_argument("--disable-blink-features=AutomationControlled")
options.add_argument("--disable-extensions")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
wait = WebDriverWait(driver, 15)

# Start URL
base_url = "https://www.tga.gov.au/resources/search-section-19a-approvals-database"
driver.get(base_url)

product_urls = []
page_number = 1

print(f"\n📄 Starting at page {page_number}")

while True:
    if max_pages and page_number > max_pages:
        print(f"🛑 Reached max page limit ({max_pages}). Stopping...")
        break

    try:
        print(f"\n🔄 Processing page {page_number}...")

        # Wait for entries
        wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, ".summary__title a")))
        entries = driver.find_elements(By.CSS_SELECTOR, ".summary__title a")
        print(f"➡️ Found {len(entries)} entries")

        # Store current first item text
        first_item_text = entries[0].text.strip() if entries else ""

        # Save URLs
        urls = [entry.get_attribute('href') for entry in entries]
        product_urls.extend(urls)

        # Click next
        try:
            time.sleep(1.5)
            next_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'li.pager__item--next a')))
            driver.execute_script("arguments[0].scrollIntoView();", next_button)
            next_button.click()
            print("⏭️ Clicked next page")

            # Wait for page to load new content
            wait.until(lambda d: d.find_element(By.CSS_SELECTOR, ".summary__title a").text.strip() != first_item_text)
            page_number += 1
            time.sleep(1.5)

        except (TimeoutException, NoSuchElementException, ElementClickInterceptedException):
            print("🚫 No more pages or pagination failed.")
            break

    except Exception as e:
        print(f"❌ Error on page {page_number}: {e}")
        break

# Save to CSV
filename = "tga_product_urls.csv"
with open(filename, "w", newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Product URL"])
    for url in product_urls:
        writer.writerow([url])

print(f"\n✅ Done. Collected {len(product_urls)} URLs.")
print(f"📁 Saved to: {filename}")
driver.quit()