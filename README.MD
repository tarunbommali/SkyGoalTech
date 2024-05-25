# User Authentication API with Express and SQLite

This is a simple user authentication API built with Express.js, SQLite, bcrypt for password hashing, and JWT for token-based authentication.

## Features

- User Signup
- User Login
- Get User Info (Protected Route)

## Prerequisites

- Node.js
- npm (Node Package Manager)
- SQLite

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/yourrepository.git
    cd yourrepository
    ```

2. Install the dependencies:

    ```sh
    npm install
    ```

3. Set up the SQLite database:

    ```sh
    touch user.db
    ```

4. Create a `.env` file and add your secret key:

    ```env
    SECRET_KEY=your_secret_key
    ```

## Running the Application

1. Start the server:

    ```sh
    npm start
    ```

2. The server will start at `http://localhost:3000/` (or the port specified in your environment variables).

## API Endpoints

### Signup

- **URL**: `/signup`
- **Method**: POST
- **Description**: Creates a new user.
- **Request Body**:

    ```json
    {
      "username": "your_username",
      "password": "your_password"
    }
    ```

- **Response**:

    ```json
    {
      "message": "User created successfully"
    }
    ```

### Login

- **URL**: `/login`
- **Method**: POST
- **Description**: Logs in a user.
- **Request Body**:

    ```json
    {
      "username": "your_username",
      "password": "your_password"
    }
    ```

- **Response**:

    ```json
    {
      "token": "your_jwt_token"
    }
    ```

### Get User Info

- **URL**: `/user`
- **Method**: GET
- **Description**: Gets the user info. This route is protected and requires a valid JWT token.
- **Headers**:

    ```http
    Authorization: your_jwt_token
    ```

- **Response**:

    ```json
    {
      "id": 1,
      "username": "your_username"
    }
    ```

## Project Structure

```plaintext
.
├── .env
├── package.json
├── server.js
└── user.db
