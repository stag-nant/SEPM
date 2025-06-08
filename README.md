# SafeCode Framework

SafeCode Framework is a web-based secure code analysis tool developed as part of an SEPM project. It allows users to scan Python code for common security vulnerabilities, get real-time feedback, and download scan reports. An admin dashboard is included for managing platform alerts and monitoring scan activity.

---

## Project Objectives

- Help developers identify security risks early in the development process.
- Provide categorized vulnerability feedback with severity levels.
- Assist users in following secure coding practices.
- Offer a clean and user-friendly interface for both users and admins.

---

## Features Implemented

1. **Code Upload and Scanning**

   - Users can paste their code and initiate a scan.
   - Identifies risky functions like `eval`, `exec`, `os.system`, etc.

2. **Real-Time Feedback**

   - Scan results are shown instantly in the web interface.
   - Each vulnerability includes severity level and fix suggestions.

3. **Report Generation**

   - Downloadable `.txt` reports are available after scans.

4. **Notification System**

   - Admins can send platform updates and view auto-alerts.

5. **Admin Dashboard**

   - View all scan logs and notifications.

6. **Mobile-Responsive UI**
   - The interface is optimized for use on various devices.

---

## Technology Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python 3, Flask
- **Database:** SQLite with SQLAlchemy ORM
- **Migrations:** Flask-Migrate (Alembic)

---

## Setup Instructions

### Clone the Repository

```bash
git clone https://github.com/stag-nant/SEPM.git
cd SEPM
```

### Create Virtual Environment

```bash
python -m venv .venv
.venv\Scripts\activate   # For Windows
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Set Up the Database

```bash
flask db init
flask db migrate -m "Initial setup"
flask db upgrade
```

### Run the Application

```bash
flask run
```

Then visit: `http://127.0.0.1:5000`

---

## Project Structure

```
project/
├── app.py
├── requirements.txt
├── templates/
│   ├── index.html
│   └── admin.html
├── static/
│   └── style.css
├── migrations/
└── safecode.db
```

---

## Author

Muhil, 3rd Year B.Tech Cybersecurity Student, SRM Institute of Science and Technology

---

## License

This project is open source. License terms can be added here if required.

---

## Future Scope

- API integration for DevOps pipelines
- Authentication system for admin login
- Deployment to cloud platforms like Render or Replit
