# QuickTask

QuickTask is a simple and user-friendly task management web application built with **Flask** and **Bootstrap**. It allows users to create, update, delete, and manage tasks with features such as due dates, priority levels, task completion toggling, and task filtering/searching.

---

## Features

- User registration and authentication
- Add new tasks with description, due date, and priority (High, Normal, Low)
- Mark tasks as completed or pending with a checkbox toggle
- Edit and delete existing tasks
- Search tasks by description
- Filter tasks by status (All, Pending, Completed)
- Sort tasks by due date or priority
- Responsive and modern UI using Bootstrap 5
- Flash messages for user feedback

---

## Screenshots

_Add screenshots here if you want, or add a gif of the app_

---

## Tech Stack

- Backend: Flask (Python)
- Frontend: HTML, Bootstrap 5, CSS
- Database: SQLite (using Flask SQLAlchemy or built-in SQLite)
- Authentication: Flask-Login

---

## Installation and Setup

1. **Clone the repository:**

``bash
git clone https://github.com/Vijaybattula26/QuickTask-Project.git
cd QuickTask-Project
Create and activate a virtual environment:

bash
Copy
Edit
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Run the app:

bash
Copy
Edit
flask run
Open your browser and visit http://127.0.0.1:5000

Usage
Register a new user account.

Log in with your credentials.

Add, update, and manage your tasks easily.

Use the filters and search bar to organize tasks.

Log out securely.

Project Structure
php
Copy
Edit
QuickTask-Project/
│
├── app.py              # Main Flask app file
├── requirements.txt    # Python dependencies
├── Procfile            # For deployment (Heroku or other platforms)
├── instance/
│   └── quicktask.db    # SQLite database (auto-created)
├── static/
│   └── style.css       # Custom CSS styles
├── templates/
│   ├── layout.html     # Base HTML layout
│   ├── index.html      # Main task management page
│   ├── login.html      # Login page
│   └── register.html   # Registration page
└── README.md           # This file
