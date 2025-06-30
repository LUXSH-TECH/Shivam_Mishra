# medsearch/serializers.py
from rest_framework import serializers
from .models import *

class WebsiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Website
        # Corrected to use 'url' field as per your model definition
        fields = ['id', 'name', 'url']

class SearchResultSerializer(serializers.ModelSerializer):
    # Include the website name directly in the result serialization
    website_name = serializers.CharField(source='website.name', read_only=True)

    class Meta:
        model = SearchResult
        # Ensure is_user_selected is included
        fields = ['id', 'website_name', 'title', 'product_url', 'position', 'is_user_selected']
        # Exclude 'search_query' and the Website object itself to keep result items cleaner
        # exclude = ['search_query', 'website']


# Serializer to handle the incoming search request data
class SearchRequestSerializer(serializers.Serializer):
    query = serializers.CharField(max_length=500)

# --- Serializer for SearchQuery with results grouped by website ---
class SearchQueryWithAllResultsSerializer(serializers.ModelSerializer):
    # This field will hold the results grouped by website name
    results = serializers.SerializerMethodField()

    class Meta:
        model = SearchQuery
        # Include the fields you want for the SearchQuery itself
        fields = ['id', 'query_text', 'timestamp', 'results'] # Include the 'results' field

    def get_results(self, obj):
        # 'obj' is the SearchQuery instance
        # Fetch all results related to this query
        # Ordering by website name and then position ensures consistent grouping and order
        all_results = obj.results.all().order_by('website__name', 'position')

        # Group results by website name
        grouped_results = {}
        for result in all_results:
            website_name = result.website.name
            if website_name not in grouped_results:
                grouped_results[website_name] = []
            # Serialize the individual result using SearchResultSerializer
            grouped_results[website_name].append(SearchResultSerializer(result).data)

        return grouped_results


class ManualCorrectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ManualCorrection
        fields = ['search_query', 'corrected_text', 'correction_timestamp']

# --- Serializers for Feedback ---
class FeedbackRequestSerializer(serializers.Serializer):
    search_id = serializers.IntegerField()
    selected_result_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, default=[]
    )
    manual_correction_text = serializers.CharField(
        max_length=500, required=False, allow_blank=True, allow_null=True
    )


class DerivedProductInstanceSerializer(serializers.ModelSerializer):
    source_result_id = serializers.PrimaryKeyRelatedField(source='source_result',read_only=True)
    source_manual_correction_id = serializers.PrimaryKeyRelatedField(source='source_manual_correction',read_only=True)

    class Meta:
        model = DerivedProductInstance
        fields = [
            'id',
            'search_query',
            'source_result_id',
            'source_manual_correction_id',
            'api',
            'strength',
            'dosage_form'
        ]


class LearnedProductSerializer(serializers.ModelSerializer):
     class Meta:
         model = LearnedProduct
         fields = ['id', 'api', 'strength', 'dosage_form', 'learning_timestamp']
         # Add related fields if you want them in the response
         # depth = 1 # Or explicitly list fields like 'derived_from_manual_entry__corrected_text'

