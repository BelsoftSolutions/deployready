from fastapi import FastAPI

app = FastAPI()


@app.get("/authors")
def authors():
    return []


@app.get("/oauth/callback")
def oauth_callback():
    return {}