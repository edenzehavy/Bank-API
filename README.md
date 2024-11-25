# Bank API Assignment (F5)

This repository contains a simple bank API implementation for a home assignment provided by F5. The API is built in Go and includes user authentication using JWT tokens and role-based access control. It allows users to register, log in, manage accounts, and check balances. Admin users can also create accounts and view all user balances.

## Features:
- **JWT Token Authentication**: Secure login using JSON Web Tokens (JWT).
- **Role-based Access**: Admin and regular user roles to control access.
- **Environment Variable for Security**: Token key is stored as an environment variable to ensure it is not visible in the code.
- **Admin Permissions**: Only admins can create accounts and view all accounts to prevent unauthorized account creation.
- **User Account Operations**: Admins can create their own accounts, deposit to them, and withdraw from them. However, they cannot perform these actions on other users' accounts.
- **Input Validation**: Ensures that input data is correctly formatted and meets necessary constraints.
- **Authorization Function**: Ensures that users can only operate on their own accounts.
- **Middlewares**: Includes JSON content-type validation for requests and a logging middleware to generate access logs.

## Tasks Completed:
1. **Security Fixes**: Identified and fixed security issues in the API.
2. **Server & Main Function**: Implemented the server and main function to handle incoming requests.
3. **Access Logging**: Added functionality to log request and response details in a structured JSON format.
4. **BOLA Detection Tool**: Developed a tool to analyze access logs for potential Broken Object Level Authorization (BOLA) security risks.

## Getting Started

To run this API locally, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/f5-bank-api-assignment.git
    ```

2. Install Go (if not already installed):
    - Download and install Go from [https://go.dev/dl/](https://go.dev/dl/).

3. Run the application:
    ```bash
    cd f5-bank-api-assignment
    go run main.go
    ```

4. The API will be available at `http://localhost:8080`.

## API Endpoints

- **POST** `/register` - Register a new user (user or admin).
- **POST** `/login` - Login to get a JWT token.
- **POST** `/accounts` - Create a new account (Admin only).
- **GET** `/accounts` - List all accounts (Admin only).
- **GET** `/balance?user_id=<id>` - Get balance for a specific user.
- **POST** `/balance` - Deposit money into a user's account.
- **DELETE** `/balance` - Withdraw money from a user's account.

## Logs and Security

- **Access Logs**: Logs request and response data in JSON format, which includes request URL, query string parameters, request body length, and response status.
- **BOLA Detection Tool**: (In another repo) Analyze the access logs for potential broken object level authorization (BOLA) attacks.


