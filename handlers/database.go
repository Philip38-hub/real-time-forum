package handlers

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,          -- UUID as TEXT
        email TEXT UNIQUE NOT NULL,
        nickname TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        age INTEGER NOT NULL,
        gender TEXT NOT NULL CHECK (gender IN ('male', 'female')),
        google_id TEXT,              -- Google's unique user ID
        github_id TEXT,               -- GitHub's unique user ID
        avatar_url TEXT,              -- Profile picture URL
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CHECK (age >= 13)            -- Minimum age requirement
    );

    CREATE TABLE IF NOT EXISTS google_auth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id)
    );

    CREATE TABLE IF NOT EXISTS github_auth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id)
    );

    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,  -- Changed from INTEGER to TEXT for UUID
        title TEXT,
        content TEXT,
        image_path TEXT, -- New column for image path
        created_at DATETIME DEFAULT (DATETIME('now', 'localtime')), -- Store in local time (EAT)
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS post_categories (
        post_id INTEGER,
        category TEXT,
        FOREIGN KEY(post_id) REFERENCES posts(id)
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER DEFAULT NULL REFERENCES comments(id) ON DELETE CASCADE,
        post_id INTEGER,
        user_id INTEGER, 
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id TEXT,
        is_like BOOLEAN, -- 1 for like, 0 for dislike
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(post_id, user_id) -- Ensure a user can only like/dislike a post once
    );

    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY NOT NULL,
        user_id TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS comment_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        comment_id INTEGER NOT NULL,
        is_like BOOLEAN NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE,
        UNIQUE(user_id, comment_id)
    );

     CREATE TABLE IF NOT EXISTS private_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id TEXT NOT NULL,       -- UUID of the sender
        receiver_id TEXT NOT NULL,     -- UUID of the receiver
        content TEXT NOT NULL,         -- Message content
        timestamp DATETIME NOT NULL,   -- Timestamp of the message
        is_read BOOLEAN DEFAULT FALSE, -- Whether the message has been read
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Index for faster queries on sender and receiver
    CREATE INDEX IF NOT EXISTS idx_private_messages_sender 
        ON private_messages(sender_id);

    CREATE INDEX IF NOT EXISTS idx_private_messages_receiver 
        ON private_messages(receiver_id);
    `
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}
