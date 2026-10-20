from fastapi import FastAPI

app = FastAPI()


def ping():
    return {"pong": True}


app.add_api_route("/ping", ping, methods=["GET"])
