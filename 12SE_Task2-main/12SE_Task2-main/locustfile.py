from locust import HttpUser, task, between

class WebsiteUser(HttpUser):
    host = "http://127.0.0.1:5000"  # Your website's base URL
    wait_time = between(1, 3)  # Simulate wait time between requests (1-3 seconds)

    @task(1)
    def login(self):
        # Simulate login request with username and password
        self.client.post("/login", data={"username": "admin", "password": "admin123"})

    def on_start(self):
        """ This method is called when a simulated user starts. """
        print("Test started")

    def on_stop(self):
        """ This method is called when a simulated user stops. """
        print("Test stopped")
