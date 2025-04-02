Base URL
http://localhost:8080

Authentication
Protected endpoints require a valid JWT token in the Authorization header:


Authorization: Bearer <your_jwt_token>
Endpoints
POST /register
Registers a new user in the system.

Request Body:


{
  "email": "user@example.com",
  "password": "securepassword"
}
Success Response (201 Created):


{
  "message": "User registered successfully",

}
Error Responses:

400 Bad Request: Invalid input data

500 Internal Server Error: Server-side error

POST /login
Authenticates a user and returns a JWT token.

Request Body:


{
  "email": "user@example.com",
  "password": "securepassword"
}
Success Response (200 OK):

{
  "message": "User registered successfully"
}
Error Responses:

400 Bad Request: Invalid input data
500 Internal Server Error: Server-side error

GET /protected
Example protected endpoint that requires authentication.

Headers:



Authorization: Bearer <your_jwt_token>
Success Response (200 OK):


{
  "message": "You are authenticated!",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "user@example.com"
  }
}
Error Responses:

401 Unauthorized: Missing or invalid token

429 Too Many Requests: Rate limit exceeded (5 requests/second)

Rate Limiting
The API enforces rate limiting of 5 requests per second per IP address. If exceeded, you'll receive:


{
  "error": "Too many requests"
}
with status code 429 Too Many Requests.

Response Codes
Code	Description
200	OK - Successful request
201	Created - Resource created
400	Bad Request - Invalid input
401	Unauthorized - Authentication failed
429	Too Many Requests - Rate limit exceeded
500	Internal Server Error - Server problem
Models
User


{
  "id": "507f1f77bcf86cd799439011",
  "email": "user@example.com",
  "createdAt": "2023-11-20T14:30:00Z",
  "updatedAt": "2023-11-20T14:30:00Z"
}
Note: Password fields are never returned in responses.

This documentation reflects the current API implementation with:

JWT authentication

Rate limiting

Automatic timestamps

Secure password handling

Structured responses