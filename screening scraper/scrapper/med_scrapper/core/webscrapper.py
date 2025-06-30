import time
import re # Import the re module
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementClickInterceptedException, WebDriverException, WebDriverException as SeleniumWebDriverException
from webdriver_manager.chrome import ChromeDriverManager
# Assuming core.models contains your Django models (SearchQuery, Website, SearchResult)
from .models import SearchQuery, Website, SearchResult # Use relative import

# Create your views here. # This comment seems misplaced if this is a scraper module

# --- Website URLs ---
MHRA_BASE_URL = "https://products.mhra.gov.uk/"
BNF_BASE_URL = "https://bnf.nice.org.uk/"
# EMC_BASE_URL = "https://www.medicines.org.uk/emc" # For later

# --- Proxy Configuration (Replace with your actual proxy details) ---
# It's better to manage this in Django settings or pass it securely
# For now, hardcoding for demonstration.
# Use the exact IP and Port that worked in your standalone test
PROXY_IP = "172.167.161.8" # Replace with your proxy IP
PROXY_PORT = "8080" # Replace with your proxy Port
USE_PROXY = False # Set to True to enable proxy

# --- WebDriver Setup ---
def get_webdriver(use_proxy=False, proxy_ip=None, proxy_port=None):
    """Sets up and returns the Chrome WebDriver, optionally with a proxy."""
    options = webdriver.ChromeOptions()
    # --- HEADLESS MODE REINSTATED ---
    options.add_argument("--headless") # Run headless in server environment
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4556.108 Safari/537.36') # Updated user agent
    # options.add_experimental_option("excludeSwitches", ["enable-automation"])
    # options.add_experimental_option('useAutomationExtension', False)

    if use_proxy and proxy_ip and proxy_port:
        proxy_address = f"{proxy_ip}:{proxy_port}"
        print(f"Attempting to configure proxy: {proxy_address}")
        proxy_argument = f'--proxy-server={proxy_address}'
        options.add_argument(proxy_argument)
        print(f"Added Chrome argument: {proxy_argument}")
        # If proxy requires authentication, you might need to use a browser extension
        # or handle it differently, which adds complexity. Assuming no auth for now.
    else:
        print("Proxy is NOT enabled or proxy details are missing.")


    try:
        print("Initializing Chrome WebDriver...")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        print("WebDriver initialized.")

        # --- Add a delay specifically after proxy setup ---
        # This delay might help the browser configure the proxy before the first navigation
        if use_proxy:
            print("Proxy was configured. Waiting for proxy connection to establish...")
            time.sleep(10) # Increased wait time slightly
            print("Proxy wait finished.")

        return driver
    except Exception as e:
        print(f"Error initializing WebDriver: {e}")
        return None

def parse_product_title(title_text):
    """
    Parses a product title string to extract API, Strength, and Dosage Form.
    It handles varying orders of Strength and Dosage Form within the title.

    Args:
        title_text (str): The product title string to parse.

    Returns:
        tuple: A tuple containing (api, strength, dosage_form) if parsed successfully,
               otherwise (None, None, None). Values are stripped of leading/trailing whitespace.
    """
    if not title_text:
        return None, None, None

    DOSAGE_FORMS_LIST = [
        'TABLETS', 'CAPSULES', 'CREAM', 'SOLUTION', 'INJECTION', 'POWDER', 'SYRUP',
        'OINTMENT', 'GEL', 'SPRAY', 'LOTION', 'SUPPOSITORY', 'DROP(?:S)?', 'SUSPENSION',
        'EMULSION', 'AMPOULE', 'VIAL', 'DISKETTES', 'SACHET', 'GRANULES', 'PESSARY',
        'DUSTING POWDER', 'ENEMA', 'IMPLANT', 'PATCH', 'SHAMPOO', 'SOAP', 'PASTE',
        'VAGINAL CREAM', 'PASTILLES', 'ORAL SOLUTION', 'ORAL SUSPENSION', 'INHALER',
        'LOZENGE', 'SUBLINGUAL TABLETS', 'FILM-COATED TABLETS', 'CHEWABLE TABLETS',
        'EFFERVESCENT TABLETS', ' NGED-RELEASE TABLETS', 'GASTRO-RESISTANT TABLETS',
        'TRANSDERMAL PATCH', 'BUCCAL TABLETS', 'ORAL DROPS', 'EAR DROPS', 'EYE DROPS',
        'NASAL DROPS', 'RECTAL SOLUTION', 'CUTANEOUS SOLUTION',
        'INJECTION', 'INFUSION', ' ORAL SUSPENSION', 'SYRUP',
        'POWDER FOR ORAL SUSPENSION', 'POWDER ORAL SOLUTION',
        'POWDER FOR INJECTION', 'NEBULISER', 'INHALATION',
        'WASH', 'TOPICAL USE', 'EXTERNAL USE', 'INTRAMUSCULAR USE',
        'INTRAVENOUS USE', 'SUBCUTANEOUS USE', 'INTRADERMAL USE',
        'INTRAOCULAR USE', 'INTRA-ARTICULAR USE', 'EPIDURAL USE',
        'INTRATHECAL USE', 'INTRA-ARTERIAL USE', 'INTRAVESICAL USE',
        'INTRAURETHRAL USE', 'INTRAUTERINE USE', 'INTRAVITREAL USE',
        'INTRAVENOUS INFUSION', 'INTRAMUSCULAR INJECTION',
        'SUBCUTANEOUS INJECTION'
    ]
    # Compile a regex pattern for dosage forms from the list
    DOSAGE_FORMS_LIST_SORTED = sorted(DOSAGE_FORMS_LIST, key=len, reverse=True)

    DOSAGE_FORMS_PATTERN = re.compile(
        r'\b(' + '|'.join(DOSAGE_FORMS_LIST_SORTED) + r')\b', re.IGNORECASE
    )

    # Group 1: (\d+(?:\.\d+)?\s*[A-Za-z]{1,5}) -> Captures "25 MG", "100 IU", "0.5mg", etc.
    # Group 2 (optional): (?:/\s*(\d+(?:\.\d+)?\s*[A-Za-z]{1,5}))? -> Captures "/5 ML", "/100ml", "/ML" etc.
    # The outer (?:...)? makes the entire /ML part optional.
    # The inner (\d+(?:\.\d+)?\s*[A-Za-z]{1,5}) is the actual capturing group for the ML part.
    # Changed from [A-Za-z]{1,5}(?:/[A-Za-z]{1,5})? to explicitly handle /ML as a separate unit
    STRENGTH_PATTERN = re.compile(
        r'\b(\d+(?:\.\d+)?\s*[A-Za-z]{1,5})(?:/\s*(\d*(?:\.\d+)?\s*[A-Za-z]{1,5}))?\b', re.IGNORECASE
    )

    api = None
    strength = None
    dosage_form = None                                                

    # --- Find Strength and Dosage Form ---
    df_match = DOSAGE_FORMS_PATTERN.search(title_text)
    s_match = STRENGTH_PATTERN.search(title_text)

    if df_match:
        dosage_form = df_match.group(1).strip()

    if s_match:
        # Group 1 will always contain the first part (e.g., "25 MG")
        strength_part1 = s_match.group(1).strip()
        # Group 2 will contain the second part (e.g., "5 ML") or None if not present
        strength_part2 = s_match.group(2)

        if strength_part2:
            # If both parts exist, combine them
            strength = f"{strength_part1}/ {strength_part2.strip()}"
        else:
            # Otherwise, just use the first part
            strength = strength_part1

    first_key_element_start = len(title_text)

    if df_match:
        first_key_element_start = min(first_key_element_start, df_match.start())
    if s_match:
        first_key_element_start = min(first_key_element_start, s_match.start())

    api = title_text[:first_key_element_start].strip()

    # --- Post-processing for API refinement ---
    api = re.sub(r'\s*(?:BP|USP|Ph\.\s*Eur\.|EP|IP|JP|BPC|NF)\s*$', '', api, flags=re.IGNORECASE).strip()
    api = api.rstrip(',.-')

    api = api if api else None

    return api, strength, dosage_form

# --- MHRA Specific Scraping Logic ---
def scrape_mhra_search(query_text, search_query_instance, website_instance, use_proxy=False, proxy_ip=None, proxy_port=None):
    """
    Performs a search on the MHRA website, handles pagination, and saves results to the database.

    Args:
        query_text (str): The product name to search for.
        search_query_instance (SearchQuery): The Django SearchQuery model instance for this search.
        website_instance (Website): The Django Website model instance for MHRA.
        use_proxy (bool): Whether to use a proxy.
        proxy_ip (str): Proxy IP address.
        proxy_port (str): Proxy port.

    Returns:
        list: A list of created SearchResult objects.
        str: An error message if scraping failed, otherwise None.
    """
    driver = None
    all_results = []
    error_message = None
    current_page = 1
    global_position_counter = 0

    try:
        driver = get_webdriver(use_proxy, proxy_ip, proxy_port)
        if not driver:
            return [], "Failed to get webdriver"

        wait = WebDriverWait(driver, 30)
        short_wait = WebDriverWait(driver, 5)

        print(f"Scraping MHRA for: {query_text}")
        driver.get(MHRA_BASE_URL)

        # --- Step 1: Handle Initial Search Page ---
        print("Attempting to find search bar...")
        search_input_locator = (By.ID, 'search')
        search_button_locator = (By.CSS_SELECTOR, 'form[role="search"] input[type="submit"]')

        try:
            time.sleep(1) # Small buffer
            search_input = wait.until(EC.presence_of_element_located(search_input_locator))
            search_button = wait.until(EC.element_to_be_clickable(search_button_locator))

            search_input.send_keys(query_text)
            print(f"Entered query: '{query_text}'")

            search_button.click()
            print("Clicked search button.")

        except (TimeoutException, NoSuchElementException) as e:
            error_message = f"Could not find search input or button on MHRA search page: {e}"
            print(error_message)
            return [], error_message

        # --- Step 2: Handle Disclaimer Page (Conditional) ---
        disclaimer_checkbox_locator = (By.ID, 'agree-checkbox')
        disclaimer_button_locator = (By.XPATH, '//button[text()="Agree" and @type="submit"]')

        try:
            short_wait.until(EC.presence_of_element_located(disclaimer_checkbox_locator))
            print("Disclaimer page detected. Attempting to agree...")

            agree_checkbox = wait.until(EC.element_to_be_clickable(disclaimer_checkbox_locator))

            if not agree_checkbox.is_selected():
                 agree_checkbox.click()
                 time.sleep(1)
                 print("Ticked disclaimer checkbox.")

            agree_button = wait.until(EC.element_to_be_clickable(disclaimer_button_locator))
            print("Agree button is now clickable.")

            agree_button.click()
            print("Clicked Agree button.")

            results_section_locator = (By.CSS_SELECTOR, 'section.column.results')
            wait.until(EC.presence_of_element_located(results_section_locator))
            print("Navigated past disclaimer to results page.")

        except TimeoutException:
            print("Disclaimer page not detected (or already accepted). Proceeding...")
            pass

        except (NoSuchElementException, ElementClickInterceptedException) as e:
             error_message = f"Error interacting with disclaimer page elements: {e}"
             print(error_message)
             return [], error_message
        except Exception as e:
            error_message = f"An unexpected error occurred on the disclaimer step: {e}"
            print(error_message)
            return [], error_message

        # --- Step 3: Handle Results Page and Pagination ---
        print("Attempting to extract search results...")
        results_section_locator = (By.CSS_SELECTOR, 'section.column.results')
        results_container_locator = (By.CSS_SELECTOR, 'dl')
        result_item_locator = (By.CSS_SELECTOR, '.search-result')
        next_button_locator = (By.XPATH, '//nav[@aria-label="Pagination Navigation"]//button[@class="arrow" and text()="Next"]')
        next_button_disabled_locator = (By.XPATH, '//nav[@aria-label="Pagination Navigation"]//button[@class="arrow" and text()="Next" and @disabled]')


        while True:
            print(f"Scraping results from page {current_page}...")

            try:
                results_section = wait.until(EC.presence_of_element_located(results_section_locator))
                results_container = results_section.find_element(*results_container_locator)

                time.sleep(2) # Pause for dynamic content

                result_elements = results_container.find_elements(*result_item_locator)

                if not result_elements:
                    print(f"No results found on page {current_page}.")
                    if current_page == 1:
                         return [], "No results found for the initial search."
                    else:
                         break

                print(f"Found {len(result_elements)} search results on page {current_page}")

                for position_on_page, element in enumerate(result_elements):
                    try:
                        link_locator = (By.CSS_SELECTOR, 'dd.right a')
                        title_locator = (By.CSS_SELECTOR, 'dd.right a p.title')
                        subtitle_locator = (By.CSS_SELECTOR, 'dd.right a p.subtitle')

                        link_element = element.find_element(*link_locator)
                        product_url = link_element.get_attribute('href')

                        title_element = element.find_element(*title_locator)
                        subtitle_element = element.find_element(*subtitle_locator)
                        # Combine title and subtitle for the full text to parse
                        full_text_to_parse = f"{title_element.text.strip()} {subtitle_element.text.strip()}".strip()

                        global_position_counter += 1

                        search_result = SearchResult(
                            search_query = search_query_instance,
                            website = website_instance,
                            title = full_text_to_parse, # Save the combined text as the title
                            product_url = product_url,
                            position = global_position_counter,
                        )
                        search_result.save()
                        all_results.append(search_result)

                    except (NoSuchElementException, Exception) as e:
                        print(f"  Error extracting data from result item at page {current_page}, position {position_on_page + 1}: {e}")


            except TimeoutException:
                error_message = f"Timed out waiting for search results container on page {current_page}. Page content might not have loaded correctly."
                print(error_message)
                break

            except Exception as e:
                error_message = f"An unexpected error occurred during results extraction on page {current_page}: {e}"
                print(error_message)
                break

            # --- Pagination Logic ---
            next_button = None
            try:
                next_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(next_button_locator))
                WebDriverWait(driver, 1).until_not(EC.presence_of_element_located(next_button_disabled_locator))
                print("Next button found and is clickable.")

            except (TimeoutException, NoSuchElementException):
                print('Next button not found, not clickable, or is disabled. Assuming last page.')
                break

            except Exception as e:
                 print(f"An unexpected error occurred while checking for 'Next' button: {e}")
                 break

            try:
                next_button.click()
                print(f"Clicked 'Next'. Moving to page {current_page + 1}.")
                current_page += 1
                time.sleep(2) # Pause after clicking next

                wait.until(EC.presence_of_element_located(results_section_locator))
                print(f"Successfully loaded page {current_page}.")

            except ElementClickInterceptedException as e:
                error_message = f"Click on 'Next' button intercepted on page {current_page}. An overlay might be blocking it: {e}"
                print(error_message)
                break
            except TimeoutException:
                 error_message = f"Timed out waiting for results section to appear after clicking 'Next' on page {current_page}. Page might not have loaded."
                 print(error_message)
                 break
            except Exception as e:
                error_message = f"An unexpected error occurred clicking 'Next' on page {current_page}: {e}"
                print(error_message)
                break

    except Exception as e:
        error_message = f"An overall error occurred during MHRA scraping: {e}"
        print(error_message)

    finally:
        if driver:
            driver.quit()

    return all_results, error_message


# --- BNF Specific Scraping Logic ---
def scrape_bnf_search(query_text, search_query_instance, website_instance, use_proxy=True, proxy_ip=None, proxy_port=None):
    """
    Performs a search on the BNF website, handles the cookie banner and terms page,
    navigates to the 'Medicinal forms' page for the first relevant result,
    extracts Oral Suspension data, and saves results to the database.

    Args:
        query_text (str): The product name to search for.
        search_query_instance (SearchQuery): The Django SearchQuery model instance for this search.
        website_instance (Website): The Django Website model instance for BNF.
        use_proxy (bool): Whether to use a proxy.
        proxy_ip (str): Proxy IP address.
        proxy_port (str): Proxy port.

    Returns:
        list: A list of created SearchResult objects.
        str: An error message if scraping failed, otherwise None.
    """
    driver = None
    all_results = []
    error_message = None

    try:
        driver = get_webdriver(use_proxy, proxy_ip, proxy_port)
        if not driver:
            return [], "Failed to get webdriver"

        wait = WebDriverWait(driver, 40) # Increased wait time slightly
        short_wait = WebDriverWait(driver, 10) # Increased short wait slightly

        print(f"Scraping BNF for: {query_text}")

        # --- Attempt to load the BNF page ---
        try:
            print(f"Attempting to load URL: {BNF_BASE_URL}")
            driver.get(BNF_BASE_URL)
            print(f"Successfully loaded URL: {driver.current_url}")
            # Add a short pause after successful load
            time.sleep(2)
        except TimeoutException:
            error_message = f"Timed out loading BNF URL: {BNF_BASE_URL}. This might indicate a proxy or network issue."
            print(error_message)
            return [], error_message
        except SeleniumWebDriverException as e:
             error_message = f"WebDriver error loading BNF URL {BNF_BASE_URL}: {e}. This could be a proxy or browser issue."
             print(error_message)
             return [], error_message
        except Exception as e:
            error_message = f"An unexpected error occurred while loading BNF URL {BNF_BASE_URL}: {e}"
            print(error_message)
            return [], error_message


        # --- Handle Cookie Banner (Conditional - Check immediately on page load) ---
        cookie_close_button_locator = (By.ID, 'ccc-close')

        try:
            print("Checking for cookie banner...")
            cookie_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(cookie_close_button_locator)) # Increased cookie wait
            print("Cookie banner detected. Attempting to close...")
            cookie_button.click()
            print("Clicked cookie close button.")
            time.sleep(1) # Small pause after closing banner
        except TimeoutException:
            print("Cookie banner not detected. Proceeding...")
            pass
        except (NoSuchElementException, ElementClickInterceptedException) as e:
             print(f"Error interacting with cookie banner close button: {e}")
             error_message = f"Warning: Could not interact with cookie banner: {e}" # Store as warning
        except Exception as e:
             print(f"An unexpected error occurred on the cookie banner step: {e}")
             error_message = f"Warning: Unexpected error on cookie banner: {e}" # Store as warning


        # --- Handle Terms Page After Initial Load (Conditional) ---
        terms_accept_button_locator = (By.ID, 'btn-accept-bnf-eula')

        try:
            print("Checking for BNF terms page after initial load...")
            terms_button = short_wait.until(EC.element_to_be_clickable(terms_accept_button_locator))
            print("BNF terms page detected. Attempting to accept terms...")
            terms_button.click()
            print("Clicked 'I accept these terms' button.")
            time.sleep(2) # Pause after accepting terms
        except TimeoutException:
            print("BNF terms page not detected after initial load. Proceeding...")
            pass
        except (NoSuchElementException, ElementClickInterceptedException) as e:
             error_message = f"Error interacting with BNF terms page button after initial load: {e}"
             print(error_message)
             # Don't return here, let it try the search
        except Exception as e:
            error_message = f"An unexpected error occurred on the BNF terms step after initial load: {e}"
            print(error_message)
            # Don't return here, let it try the search

        # --- Step 1: Handle Initial Search Page ---
        print("Attempting to find search bar on BNF...")
        search_input_locator = (By.ID, 'autocomplete')
        search_button_locator = (By.CSS_SELECTOR, 'button[type="submit"][aria-label="Perform search"]')

        try:
            time.sleep(1) # Small buffer before finding search elements
            search_input = wait.until(EC.presence_of_element_located(search_input_locator))
            search_button = wait.until(EC.element_to_be_clickable(search_button_locator))

            search_input.send_keys(query_text)
            print(f"Entered query: '{query_text}'")

            search_button.click()
            print("Clicked search button.")

            # --- Handle Terms Page After Search (Conditional - Check again) ---
            try:
                print("Checking for BNF terms page after search click...")
                terms_button = short_wait.until(EC.element_to_be_clickable(terms_accept_button_locator))
                print("BNF terms page detected after search click. Attempting to accept terms...")
                terms_button.click()
                print("Clicked 'I accept these terms' button.")
                time.sleep(2) # Pause after accepting terms
            except TimeoutException:
                print("BNF terms page not detected after search click. Proceeding...")
                pass
            except (NoSuchElementException, ElementClickInterceptedException) as e:
                 error_message = f"Error interacting with BNF terms page button after search click: {e}"
                 print(error_message)
                 return [], error_message # Exit if terms interaction fails
            except Exception as e:
                error_message = f"An unexpected error occurred on the BNF terms step after search click: {e}"
                print(error_message)
                return [], error_message

            # --- Wait for Search Results to Load ---
            print(f"Current URL after search and pop-ups: {driver.current_url}")

            # --- More general wait for *any* search result item ---
            general_result_item_locator = (By.CSS_SELECTOR, 'header.card__header')
            first_result_link_locator = (By.CSS_SELECTOR, 'header.card__header a[href*="medicinal-forms/"]')

            try:
                # Wait for at least one general result item to be present
                wait.until(EC.presence_of_element_located(general_result_item_locator))
                print("BNF search results container element found.")

                # Now, wait for the specific 'medicinal-forms/' link within those results
                wait.until(EC.presence_of_element_located(first_result_link_locator))   
                print("Specific 'Medicinal forms' link found on BNF results page.")

            except TimeoutException:
                error_message = f"Timed out waiting for BNF search results or 'Medicinal forms' link. Verify query and locators. Current URL: {driver.current_url}"
                print(error_message)
                return [], error_message # Exit if results or link are not found

            print("BNF search results page loaded.")

        except (TimeoutException, NoSuchElementException) as e:
            error_message = f"Could not find search input or button on BNF initial search page: {e}"
            print(error_message)
            return [], error_message
        except Exception as e:
            error_message = f"An unexpected error occurred on BNF initial search step: {e}"
            print(error_message)
            return [], error_message


        # --- Step 2: Navigate to 'Medicinal forms' page ---
        print("Attempting to find and click 'Medicinal forms' link...")
        medicinal_forms_link_locator = (By.CSS_SELECTOR, 'header.card__header a[href*="medicinal-forms/"]')

        try:
            medicinal_forms_link = wait.until(EC.element_to_be_clickable(medicinal_forms_link_locator))
            product_url = medicinal_forms_link.get_attribute('href')

            print(f"Found 'Medicinal forms' link: {product_url}")
            medicinal_forms_link.click()
            print("Clicked 'Medicinal forms' link.")

            # Wait for the Medicinal forms page to load
            oral_suspension_parent_section_locator = (By.XPATH, '//section[@aria-labelledby="oral-suspension"]')
            wait.until(EC.presence_of_element_located(oral_suspension_parent_section_locator))
            print("Navigated to Medicinal forms page.")

        except (TimeoutException, NoSuchElementException) as e:
             error_message = f"Could not find or click 'Medicinal forms' link or wait for next page on BNF: {e}"
             print(error_message)
             return [], error_message
        except ElementClickInterceptedException as e:
             error_message = f"Click on 'Medicinal forms' link intercepted on BNF: {e}"
             print(error_message)
             return [], error_message
        except Exception as e:
            error_message = f"An unexpected error occurred on BNF navigation step: {e}"
            print(error_message)
            return [], error_message


        # --- Step 3: Extract Oral Suspension Data ---
        print("Attempting to extract Oral Suspension data from BNF...")
        oral_suspension_section_locator = (By.XPATH, '//section[@aria-labelledby="oral-suspension"]')
        show_all_button_locator = (By.XPATH, './/button[contains(@class, "AccordionGroup-module--toggleButton")]')
        show_more_button_locator = (By.XPATH, './/button[contains(@class, "Accordion-module--toggleLabel")]')
        prep_list_locator = (By.CSS_SELECTOR, 'ol.medicinal-forms-module--prepList--5fed2')
        prep_item_locator = (By.CSS_SELECTOR, 'li')
        heading_text_locator = (By.CSS_SELECTOR, 'h3.Prep-module--prepHeading--33064 span.Prep-module--headingText--18fe6')
        active_ingredients_locator = (By.XPATH, './/dt[text()="Active ingredients"]/following-sibling::dd/div')
        # You can add locators for Size, Unit, etc. similarly

        try:
            oral_suspension_section = wait.until(EC.presence_of_element_located(oral_suspension_section_locator))

            # Check if there's a "Show all" button and click it if needed
            try:
                show_all_button = oral_suspension_section.find_element(*show_all_button_locator)
                if show_all_button.get_attribute('aria-expanded') == 'false':
                     print("Clicking 'Show all' button for Oral Suspension...")
                     show_all_button.click()
                     time.sleep(2) # Adjust based on how long it takes for content to load

            except NoSuchElementException:
                print("'Show all' button not found for Oral Suspension (maybe already expanded or no items).")
                pass

            try:
                show_more_button = oral_suspension_section.find_element(*show_more_button_locator)
                if show_all_button.get_attribute('aria-hidden') == 'false':
                    print("clicking 'Show More' for Oral Suspension...")
                    show_all_button.click()
                    time.sleep(2)

            except NoSuchElementException:
                print("Show more not found in the template")
                pass

            prep_list = oral_suspension_section.find_element(*prep_list_locator)
            prep_items = prep_list.find_elements(*prep_item_locator)

            if not prep_items:
                 print("No Oral Suspension product items found on BNF.")
                 return [], None

            print(f"Found {len(prep_items)} Oral Suspension product items on BNF.")

            for position_on_page, item_element in enumerate(prep_items):
                 try:
                     heading_element = item_element.find_element(*heading_text_locator)
                     full_title = heading_element.text.strip()

                     active_ingredients = None
                     try:
                         active_ingredients_element = item_element.find_element(*active_ingredients_locator)
                         active_ingredients = active_ingredients_element.text.strip()
                     except NoSuchElementException:
                         pass

                     # --- Save Result to Database ---
                     search_result = SearchResult(
                         search_query=search_query_instance,
                         website=website_instance,
                         title=full_title,
                         product_url=driver.current_url, # URL of the current page
                         position=position_on_page + 1, # Position within the Oral Suspension list
                         raw_data={'active_ingredients': active_ingredients} # Optional: save extra data
                     )
                     search_result.save()
                     all_results.append(search_result)


                 except (NoSuchElementException, Exception) as e:
                     print(f"  Error extracting data from BNF Oral Suspension item at position {position_on_page + 1}: {e}")


        except TimeoutException:
            error_message = "Timed out waiting for Oral Suspension section or prep list on BNF Medicinal forms page."
            print(error_message)
        except NoSuchElementException:
             error_message = "Could not find Oral Suspension section or prep list on BNF Medicinal forms page."
             print(error_message)
        except Exception as e:
            error_message = f"An unexpected error occurred during BNF Oral Suspension extraction: {e}"
            print(error_message)


    except Exception as e:
        error_message = f"An overall error occurred during BNF scraping: {e}"
        print(error_message)

    finally:
        if driver:
            driver.quit()

    return all_results, error_message

# --- Remember to update your Django views (views.py) to call both scrapers ---
# and update your Django serializers and Flask UI to handle results from both sites.
