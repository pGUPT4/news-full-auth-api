from django.conf import settings
import requests
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
import boto3
import json
import logging

logger = logging.getLogger(__name__)


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get('access')
            refresh_token = response.data.get('refresh')

            response.set_cookie(
                'access',
                access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )
            response.set_cookie(
                'refresh',
                refresh_token,
                max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh')

        if refresh_token:
            request.data['refresh'] = refresh_token

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get('access')

            response.set_cookie(
                'access',
                access_token,
                max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
                path=settings.AUTH_COOKIE_PATH,
                secure=settings.AUTH_COOKIE_SECURE,
                httponly=settings.AUTH_COOKIE_HTTP_ONLY,
                samesite=settings.AUTH_COOKIE_SAMESITE
            )

        return response


class CustomTokenVerifyView(TokenVerifyView):
    def post(self, request, *args, **kwargs):
        access_token = request.COOKIES.get('access')

        if access_token:
            request.data['token'] = access_token

        return super().post(request, *args, **kwargs)


class LogoutView(APIView):
    def post(self, request, *args, **kwargs):
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie('access')
        response.delete_cookie('refresh')

        return response


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
import requests
from django.conf import settings

class NewsGaloreView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        preferences = user.preferences if hasattr(user, 'preferences') else []
        function_url = "https://faas-nyc1-2ef2e6cc.doserverless.co/api/v1/web/fn-619663bc-cdfa-4fb1-ae8b-9a4ba18a6346/default/news-filter"
        try:
            response = requests.post(function_url, json={"user_id": user.email, "preferences": preferences})
            data = response.json()
            if data["statusCode"] != 200:
                return Response({"error": data["body"]["error"]}, status=data["statusCode"])
            return Response(data["body"], status=200)
        except requests.RequestException as e:
            return Response({"error": str(e)}, status=500)

class RawNewsView(APIView):
    def get(self, request):
        current_time = datetime.now()
        cache_timeout = timedelta(minutes=5)
        cache = getattr(settings, 'NEWS_CACHE', {"data": None, "timestamp": None})

        # Rate limiting (10 requests/min)
        request_queue = getattr(settings, 'REQUEST_QUEUE', deque(maxlen=10))
        while request_queue and (current_time - request_queue[0] > timedelta(minutes=1)):
            request_queue.popleft()
        if len(request_queue) >= 10:
            logger.warning("Rate limit exceeded")
            if cache["data"] and (current_time - cache["timestamp"] < cache_timeout):
                return Response(cache["data"], status=200)
            return Response({"error": "Rate limit exceeded"}, status=429)

        try:
            url = "http://api.nytimes.com/svc/news/v3/content/all/all.json"
            params = {"api-key": settings.NYT_API_KEY}
            response = requests.get(url, params=params)
            response.raise_for_status()
            news_data = response.json()["results"]
            cache["data"] = news_data
            cache["timestamp"] = current_time
            request_queue.append(current_time)
            settings.NEWS_CACHE = cache
            settings.REQUEST_QUEUE = request_queue

            # Upload to S3
            s3 = boto3.client(
                "s3",
                aws_access_key_id=settings.AWS_S3_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_S3_SECRET_ACCESS_KEY
            )
            key = f"raw/news-{current_time.strftime('%Y-%m-%d-%H-%M-%S')}.json"
            s3.put_object(
                Bucket=settings.AWS_STORAGE_BUCKET_NAME,
                Key=key,
                Body=json.dumps(news_data),
                ContentType="application/json"
            )
            logger.info(f"Uploaded news to S3: {key}")

            return Response(news_data, status=200)
        except requests.RequestException as e:
            logger.error(f"NYT API failed: {str(e)}")
            if response.status_code == 429 and cache["data"] and (current_time - cache["timestamp"] < cache_timeout):
                return Response(cache["data"], status=200)
            return Response({"error": str(e)}, status=500)