from rest_framework.pagination import PageNumberPagination

class CustomPagination(PageNumberPagination):
    def get_page_size(self, request):
        # Default to 10 if 'page_size' is not provided or invalid
        page_size = request.query_params.get('page_size', 10)
        
        try:
            # Ensure the 'page_size' is an integer and within a reasonable range
            page_size = int(page_size)
            if page_size <= 0:
                page_size = 10  # Fallback to 10 if page_size is non-positive
        except (ValueError, TypeError):
            # Default to 10 if it's not a valid integer
            page_size = 10
        
        return page_size