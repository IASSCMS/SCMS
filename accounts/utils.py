from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

def custom_exception_handler(exc, context):
    """
    Custom exception handler for DRF that returns standardized error responses
    """
    # Call REST framework's default exception handler first to get the standard error response
    response = exception_handler(exc, context)
    
    # If response is None, it means DRF doesn't handle this exception by default
    if response is None:
        # Generic server error for unhandled exceptions
        return Response({
            'success': False,
            'message': 'An unexpected error occurred',
            'error': str(exc)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Create a custom error response format
    error_data = {
        'success': False,
        'message': str(exc),
    }
    
    # Add field errors if available
    if hasattr(response, 'data') and isinstance(response.data, dict):
        if 'detail' in response.data:
            error_data['message'] = response.data['detail']
        
        # Include field-specific errors if available
        field_errors = {}
        for field, errors in response.data.items():
            if field != 'detail':
                if isinstance(errors, list):
                    field_errors[field] = errors[0] if errors else 'Invalid data'
                else:
                    field_errors[field] = str(errors)
        
        if field_errors:
            error_data['field_errors'] = field_errors
    
    return Response(error_data, status=response.status_code)