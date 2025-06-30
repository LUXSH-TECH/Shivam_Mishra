from django.shortcuts import render, get_object_or_404, HttpResponse
from django.http import FileResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import ListAPIView
from django.utils import timezone
import csv
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4

# Import your models
from .models import SearchQuery, SearchResult, Website, ManualCorrection, LearnedProduct, DerivedProductInstance # Import DerivedProductInstance
# Import your serializers
from .serializers import (
    SearchRequestSerializer,
    SearchQueryWithAllResultsSerializer,
    FeedbackRequestSerializer,
    LearnedProductSerializer,
    SearchResultSerializer,
    DerivedProductInstanceSerializer,
    ManualCorrectionSerializer # Import the new serializer
)
# Import your scraper functions AND the parsing function
from .webscrapper import scrape_mhra_search, scrape_bnf_search, parse_product_title # Import parse_product_title

# --- Configuration ---
# Fetch Website objects once when the Django app loads
# These should match the 'name' field in your Website model instances in the DB
MHRA_WEBSITE_OBJ = None
BNF_WEBSITE_OBJ = None
EMC_WEBSITE_OBJ = None # For later

try:
    MHRA_WEBSITE_OBJ = Website.objects.get(name='MHRA Products')
    print("Successfully retrieved MHRA Website object from DB.")
except Website.DoesNotExist:
    print("ERROR: MHRA Website object not found in database. Please create a Website object with name='MHRA Products'. MHRA scraping will be skipped.")
except Exception as e:
    print(f"ERROR: Unexpected error fetching MHRA Website object: {e}. MHRA scraping will be skipped.")

try:
    BNF_WEBSITE_OBJ = Website.objects.get(name='BNF')
    print("Successfully retrieved BNF Website object from DB.")
except Website.DoesNotExist:
    print("ERROR: BNF Website object not found in database. Please create a Website object with name='BNF'. BNF scraping will be skipped.")
except Exception as e:
    print(f"ERROR: Unexpected error fetching BNF Website object: {e}. BNF scraping will be skipped.")

try:
    EMC_WEBSITE_OBJ = Website.objects.get(name='EMC')
    print("Successfully retrieved EMC Website object from DB.")
except Website.DoesNotExist:
    print("ERROR: EMC Website object not found in database. Please create a Website object with name='EMC'. EMC scraping will be skipped.")
except Exception as e:
    print(f"ERROR: Unexpected error fetching EMC Website object: {e}. EMC scraping will be skipped.")

USE_PROXY = True
PROXY_IP = "172.167.161.8" 
PROXY_PORT = "8080" 
current_date = timezone.now().strftime('%Y-%m-%d')

print(f"Views.py Proxy Configuration: USE_PROXY={USE_PROXY}, PROXY_IP={PROXY_IP}, PROXY_PORT={PROXY_PORT}")


class SearchAPIView(APIView):
    """
    API endpoint to receive search query, trigger scraping for all configured
    websites, save results, and return them grouped by website.

    NOTE: Synchronous scraping within a web request is blocking and
    NOT recommended for production. Consider using a task queue (Celery)
    for asynchronous processing in a production environment.
    """
    def post(self, request, *args, **kwargs):
        # Validate incoming request data
        serializer = SearchRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True) # Raise exception if data is invalid (sends 400 response)
        query_text = serializer.validated_data['query']

        # --- 1. Create SearchQuery record immediately ---
        try:
            search_query = SearchQuery.objects.create(query_text=query_text)
            print(f"Created SearchQuery ID: {search_query.id} for query: '{query_text}'")
        except Exception as e:
             print(f"Error creating SearchQuery: {e}")
             return Response(
                 {"error": f"Database error creating search query: {e}"},
                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
             )

        # --- 2. Trigger Scraping for all configured websites ---
        # This is the blocking part - runs scrapers sequentially
        all_scraped_results = [] # Not strictly needed for saving, but can be useful
        scraping_errors = {} # Dictionary to store errors per website

        # Scrape MHRA
        if MHRA_WEBSITE_OBJ:
            print(f"Starting MHRA scraping for SearchQuery ID {search_query.id}...")
            mhra_results, mhra_error = scrape_mhra_search(
                query_text,
                search_query,
                MHRA_WEBSITE_OBJ,
            )
            all_scraped_results.extend(mhra_results)
            if mhra_error:
                scraping_errors[MHRA_WEBSITE_OBJ.name] = mhra_error
                print(f"MHRA scraping finished with error: {mhra_error}")
            else:
                 print(f"MHRA scraping finished successfully. Found {len(mhra_results)} results.")
        else:
             scraping_errors['MHRA Products'] = "MHRA Website object not configured or failed to fetch."
             print("Skipping MHRA scraping: Website object not configured.")


        # Scrape BNF
        if BNF_WEBSITE_OBJ:
            print(f"Starting BNF scraping for SearchQuery ID {search_query.id}...")
            bnf_results, bnf_error = scrape_bnf_search(
                query_text,
                search_query,
                BNF_WEBSITE_OBJ,
                # Pass proxy config from views.py
                use_proxy=USE_PROXY,
                proxy_ip=PROXY_IP,
                proxy_port=PROXY_PORT
            )
            all_scraped_results.extend(bnf_results)
            if bnf_error:
                scraping_errors[BNF_WEBSITE_OBJ.name] = bnf_error
                print(f"BNF scraping finished with error: {bnf_error}")
            else:
                 print(f"BNF scraping finished successfully. Found {len(bnf_results)} results.")
        else:
             scraping_errors['BNF'] = "BNF Website object not configured or failed to fetch."
             print("Skipping BNF scraping: Website object not configured.")

        # --- Add scraping calls for other websites here later (e.g., emc) ---
        # if EMC_WEBSITE_OBJ:
        #    emc_results, emc_error = scrape_emc_search(...)
        #    all_scraped_results.extend(emc_results)
        #    if emc_error:
        #        scraping_errors[EMC_WEBSITE_OBJ.name] = emc_error


        # --- 3. Prepare Response ---
        # The scraper functions already saved the results to the DB.
        # We need to fetch the SearchQuery again to get all related results
        # from all websites for serialization.
        try:
            # Use prefetch_related to get all results and their related websites efficiently
            search_query_with_results = SearchQuery.objects.prefetch_related('results__website').get(id=search_query.id)

            # Use the new serializer that groups results by website
            response_serializer = SearchQueryWithAllResultsSerializer(search_query_with_results)
            response_data = response_serializer.data

            # Add scraping errors to the response data if any occurred
            if scraping_errors:
                 response_data['scraping_errors'] = scraping_errors
                 # Optionally adjust status code if all scraping failed
                 # if not all_scraped_results: # Check if the combined list is empty
                 #      status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
                 # else:
                 #      status_code = status.HTTP_200_OK # Still return partial results

            print(f"Successfully serialized results for SearchQuery ID {search_query.id}")
            # Always return 200 OK if the SearchQuery was successfully created,
            # even if scraping had errors. The errors are included in the response body.
            return Response(response_data, status=status.HTTP_200_OK)

        except SearchQuery.DoesNotExist:
            # This case should ideally not happen if we just created and scraped for it
            return Response(
                {"error": "Internal server error: Search query disappeared after scraping."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
             print(f"Error preparing response for SearchQuery ID {search_query.id}: {e}")
             return Response(
                 {"error": f"Internal server error preparing response: {e}"},
                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
             )


class SearchFeedbackAPIView(APIView):
    """
    API endpoint to receive user feedback (selected result IDs or manual entry)
    for a specific search query.

    This view updates the database based on user selections and creates
    DerivedProductInstance records based on parsed data.
    """
    def post(self, request, *args, **kwargs):
        # Validate incoming feedback data
        serializer = FeedbackRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True) # Raise exception if data is invalid (sends 400 response)

        search_id = serializer.validated_data['search_id']
        selected_result_ids = serializer.validated_data.get('selected_result_ids', [])
        manual_correction_text = serializer.validated_data.get('manual_correction_text', '').strip()

        # Retrieve the associated SearchQuery
        search_query = get_object_or_404(SearchQuery, id=search_id)
        print(f"Received feedback for SearchQuery ID: {search_id}")
        print(f"Received selected_result_ids: {selected_result_ids}") # Log received IDs
        print(f"Received manual_correction_text: '{manual_correction_text}'") # Log received text

        # --- 1. Process User Feedback ---

        # Clear any previous user selections for this search query
        SearchResult.objects.filter(search_query=search_query, is_user_selected=True).update(is_user_selected=False)
        print(f"Cleared previous user selections for SearchQuery {search_id}.")

        # Mark the newly selected SearchResults 
        valid_selected_results_qs = SearchResult.objects.filter( 
            search_query=search_query,
            id__in=selected_result_ids
        )
        updated_count = valid_selected_results_qs.update(is_user_selected=True)
        print(f"Marked {updated_count} results as user selected for SearchQuery {search_id}. IDs marked: {[r.id for r in valid_selected_results_qs]}")

        # Handle Manual Correction
        manual_correction_instance = None
        if manual_correction_text: 
            manual_correction_instance, created = ManualCorrection.objects.update_or_create(
                search_query=search_query,
                defaults={'corrected_text': manual_correction_text}
            )
            print(f"Manual correction {'created' if created else 'updated'} for SearchQuery {search_id}.")

            # --- Create DerivedProductInstance from Manual Correction ---
            print(f"Attempting to derive structured product from manual correction: '{manual_correction_instance.corrected_text}'")
            derived_api, derived_strength, derived_dosage_form = parse_product_title(manual_correction_instance.corrected_text)

            if derived_api or derived_strength or derived_dosage_form:
                try:
                    DerivedProductInstance.objects.create(
                        search_query=search_query,
                        source_manual_correction=manual_correction_instance,
                        api=derived_api,
                        strength=derived_strength,
                        dosage_form=derived_dosage_form
                    )
                    print(f"  Created DerivedProductInstance from Manual Correction ID {manual_correction_instance.id}.")
                except Exception as e:
                    print(f"  Error creating DerivedProductInstance from manual correction: {e}")
            else:  
                 print("  Could not derive structured product from manual correction.")
            
        if not manual_correction_instance and valid_selected_results_qs.exists():
             print(f"Processing {valid_selected_results_qs.count()} selected results for derivation.")
             created_instances_count = 0
             # Iterate through selected results and try to parse each one
             for result in valid_selected_results_qs:
                 print(f"    Attempting to parse result title: '{result.title}' (ID: {result.id})")
                 pdf_url = result.product_url
                 api, strength, dosage_form = parse_product_title(result.title)
                
                 print(f"    Parsing result ID {result.id} yielded: API='{api}', Strength='{strength}', Dosage Form='{dosage_form}'")

                 if api or strength or dosage_form:
                     try:
                         DerivedProductInstance.objects.create(
                             search_query=search_query,
                             source_result=result,
                             pdf_url = pdf_url,
                             api=api,
                             strength=strength,
                             dosage_form=dosage_form
                         )
                         print(f"    Created DerivedProductInstance from SearchResult ID {result.id}.")
                         created_instances_count += 1
                     except Exception as e:
                         print(f"    Error creating DerivedProductInstance from SearchResult ID {result.id}: {e}")
                 else:
                      print(f"    Could not derive structured product from SearchResult ID {result.id}.")

             print(f"Finished processing selected results. Created {created_instances_count} DerivedProductInstance(s).")

        derived_instances = DerivedProductInstance.objects.filter(search_query=search_id).order_by('-derived_timestamp')
        response_serializer = DerivedProductInstanceSerializer(derived_instances, many=True)

        response_data = {
            "message": "Feedback processed.",
            "derived_product_instances": response_serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)


class DerivedProductInstanceCSV(APIView):
    def get(self, request):
        derived_product_instances = DerivedProductInstance.objects.all()

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="derived_product_instances{current_date}.csv"'

        writer = csv.writer(response)

        writer.writerow([
            'Search Query',
            'Source Result',
            'Source Manual Correction',
            'API',
            'Strength',
            'Dosage Form',
        ])

        # Write data rows
        for instance in derived_product_instances:
            writer.writerow([
                instance.search_query.query_text if instance.search_query else '',
                instance.source_result.title if instance.source_result else '',
                instance.source_manual_correction.corrected_text if instance.source_manual_correction else '',
                instance.api,
                instance.strength,
                instance.dosage_form
            ])

        return response


class DerivedProductinstanceListView(ListAPIView):
    queryset = DerivedProductInstance
    serializer_class = DerivedProductInstanceSerializer


class LearnedproductListView(ListAPIView):
    queryset = LearnedProduct.objects.all()
    serializer_class = LearnedProductSerializer


class ManualCorrectionListView(ListAPIView):
    queryset = ManualCorrection.objects.all()
    serializer_class = ManualCorrectionSerializer

 