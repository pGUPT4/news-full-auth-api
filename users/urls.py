from django.urls import path
from .views import (
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    CustomTokenVerifyView,
    LogoutView,
    NewsGaloreView,
    RawNewsView

)

urlpatterns = [
    path('jwt/create/', CustomTokenObtainPairView.as_view()),
    path('jwt/refresh/', CustomTokenRefreshView.as_view()),
    path('jwt/verify/', CustomTokenVerifyView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('news-galore/', NewsGaloreView.as_view(), name="news_galore"),
    path('raw/', RawNewsView.as_view(), name="raw_news"),
]
