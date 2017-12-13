# ShopMe
A simple demo catalog web application with Google OAuth
Store and query data using an SQL database
API JSON endpoints for all catalog data

Matt Bladek


## Dependencies of Software and Libraries Used
The application was developed using Vagrant 2.0.1 and Virtual Box virtual environment 2.3.5
virtualizing Ubuntu 16.04-i386


* Python 2.7.11
	* SQLite 3.9.2
	* Flask 0.9
	* SQLAlchemy 1.0.12
	* oauth2client
	* httplib2
	* json
	* requests
* Bootstrap
	- HTML, CSS library
* Jquery - Javascript library utilized for API calls more specifically the AJAX library for asynchronous calls
* Google API - OAuth2 - Used for authentication and authorization

## Files
The following are the project files for the successful execution of the webserver.
* database_setup.py
Initializes a local SQL database and provides functionality for JSON API endpoints for our data

* application.py
The main python web server provides all routing, authentication, and CRUD functionality.

* client_secrets.json (not included)
Contains the information needed for Google API OAuth2 to authenticate sessions

* html
The html, css, and js for the project is contained the templates and static folders.

### Hosting
The project is hosted on a local server
* http://localhost:8000

### Instructions on Running the Demo web application
1) Install the required dependencies and software as described above
2) Launch the virtual environment using the commands vagrant up and vagrant ssh in the terminal
3) Set up the database for the webserver by executing the python script database_setup.py using the command python database_setup.py
4) Run the web server by executing the python file using the command python application.py