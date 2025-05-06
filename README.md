# Web Forum Project

## Project Overview
This project aims to build an enhanced web forum where users can interact through posts, comments, and private messages—all in real time. The forum will support live discussions via WebSockets and maintain a seamless user experience with a single-page application architecture.

## Features
### User Authentication

#### Enhanced Registration:
   - Required fields: Nickname, Age, Gender, First Name, Last Name, Email, Password
   - Email verification (bonus feature)
   - Password encryption using bcrypt

#### Flexible Login:
   - Login via nickname OR email + password
   - Single active session enforcement
   - Persistent sessions with secure cookies

### Content Management

#### Posts:
   - Category-based organization
   - Rich text formatting (markdown support)
   - Real-time updates when new posts are created

#### Comments:
   - Nested comment threads
   - Live updates without page refresh
   - @mention notifications

### Private Messaging

#### Real-time Chat:
   - Online/offline user indicators
   - Message history with infinite scroll (10 messages per load)
   - Typing indicators
   - Read receipts
   - Organized by last message activity

#### Chat Interface:
   - Persistent sidebar showing online users
   - Responsive design (collapses to bubble on smaller screens)
   - Message formatting with timestamps

## Technologies Used

- **Backend**: Go (Golang) with webSockets
- **Database**: SQLite for data storage
- **Frontend**: HTML, CSS, JavaScript (no frameworks or libraries)
- **Containerization**: Docker
- **Password Encryption**: bcrypt (Bonus)
- **Session Management**: UUID (Bonus)
- **WebSockets**: Used in both backend and frontend for live interactions

---
## Setup Instructions

### Prerequisites
- Docker installed on your machine.
- Basic knowledge of Go and SQL.

### Steps to Run the Project
To install this project, follow these steps:
1. Clone the repository: 
   ```bash
   git clone https://learn.zone01kisumu.ke/git/pochieng/real-time-forum
2. Navigate to the project directory:
   ```bash
   cd real-time-forum
   ```
3. Install the required dependencies:
   ```bash
   go get ./...
   ```

## Usage
To run the project with docker, use the following command:
1. Make it executable with this command
```bash
chmod +x script.sh
```
2. Run with this command
```bash
./script.sh
```
- This script will stop and remove any existing container, build the Docker image, and run the container, making it accessible on port 8080.

## Usage without docker
- Run with
``` go
go run .
```

## Testing & Troubleshooting
To run tests, use:
```bash
go test ./...
```
Common issues:
- **Port Conflict**: If you see a "port already in use" error, check for other applications using port 8081.
- **Database Issues**: Verify your database configuration if you encounter connection problems.

## Contributing
We welcome contributions! Please follow these guidelines:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a clear description of your changes.


## Authors
- Philip Ochieng - [GitHub Profile](https://github.com/Philip38-hub)
- Stephen Kisengese - [GitHub Profile](https://github.com/stkisengese)



## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.