# LockBox RESTful API

The LockBox API is a RESTful API following the MVC architecture, designed to support password management, encryption, and secure user authentication for the LockBox Chrome Extension.

## Base URL

`http://localhost:5434`

## Authentication

The API authenticates users using username and password. Upon successful login, it generates a JWT token that expires after a fixed time period. Once the token expires, users are automatically logged out and must log in again to continue using the API. For every request, the JWT token must accompany the request to authenticate the user.

## Endpoints

### Fetch All Users' Passwords

- Endpoint: `GET /allPassword`
  - Description: Retrieves all users' passwords.
  
### Register User

- Endpoint: `POST /`
  - Description: Inserts the user ID.

### User Login

- Endpoint: `POST /login`
  - Description: Handles user login.

### Store Ciphered Password

- Endpoint: `POST /setPassword`
  - Description: Stores ciphered passwords.

### Fetch Ciphered and Hashed Password

- Endpoint: `POST /getPassword`
  - Description: Retrieves ciphered and hashed passwords.

### Delete User

- Endpoint: `DELETE /delete`
  - Description: Deletes users.

## Usage

To interact with the LockBox API, ensure you authenticate with your credentials to receive a JWT token. Utilize the provided endpoints to manage passwords, create encrypted passwords, store cryptographic hashes, and delete users.

