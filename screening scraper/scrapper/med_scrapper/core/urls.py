from django.urls import path
from .views import *

urlpatterns = [
    path('search/', SearchAPIView.as_view(), name='search_api'),
    path('search/feedback/', SearchFeedbackAPIView.as_view(), name='search_result_detail_api'),
    path('learned_product_list/', LearnedproductListView.as_view(), name='learned-product-list'),
    path('manual_correction_list/', ManualCorrectionListView.as_view(), name='manual-correction-list'),
    path('derived_product_instance_list/', DerivedProductinstanceListView.as_view(), name='derived-product-instance-list'),
    ]