import jwt
import boto3
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework import status
from datetime import datetime, timedelta, timezone

from decouple import Config
config = Config()

AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
AWS_REGION = config('AWS_REGION')

# DnamoDB Setup
dynamodb = boto3.resource('dynamodb', 
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION)

table = dynamodb.Table('Users')

SECRET_KEY = "DDB-SECRET"

@api_view(['POST'])
def register(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return JsonResponse({'error': 'email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the user already exists
    response = table.get_item(Key={'email': email})
    if 'Item' in response:
        return JsonResponse({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

    # Create a new user and save to DynamoDb
    table.put_item(Item={'email': email, 'password': password})

    return JsonResponse({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return JsonResponse({'error': 'email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the user exists
    response = table.get_item(Key={'email': email})
    if 'Item' not in response:
        return JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the password is correct
    if response['Item']['password'] != password:
        return JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate a JWT token
    token = jwt.encode({'email': email, 'exp': datetime.now(timezone.utc) + timedelta(hours=1)}, SECRET_KEY, algorithm='HS256')

    return JsonResponse({'token': token}, status=status.HTTP_200_OK)


@api_view(['POST'])
def profile(request):
    # token = request.data.get('token')
    token = request.headers.get('Authorization').split(' ')[1]

    if not token:
        return JsonResponse({'error': 'token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = payload['email']

        # Check if the user exists
        response = table.get_item(Key={'email': email})
        if 'Item' not in response:
            return JsonResponse({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        return JsonResponse({'email': email}, status=status.HTTP_200_OK)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired'}, status=status.HTTP_400_BAD_REQUEST)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
