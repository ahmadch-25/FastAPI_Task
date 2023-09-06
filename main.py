import uuid

from fastapi import FastAPI, Depends, HTTPException
from auth import authenticate_user
import cachetools
from schemas import User, TokenResponse, PostSchema
import secrets
import hashlib
app = FastAPI()
cache = cachetools.LFUCache(maxsize=1000)
token_cache = cachetools.LFUCache(maxsize=1000)
post_cache = cachetools.LFUCache(maxsize=1000)
response_cache = cachetools.TTLCache(maxsize=1000, ttl=300)



def generate_token():
    return secrets.token_hex(32)  # Generate a 256-bit (32-byte) random token

# Function to create a password hash
def get_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.post("/signup", response_model=TokenResponse)
def signup(user: User):
    email = user.email
    password = user.password
    if email in cache:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(password)
    # Generate a random token (you can replace this with JWT generation)
    token = generate_token()
    cache[email] = {
        "email": email,
        "password": hashed_password,
        "token": token
    }
    token_cache[token] = email

    return {"access_token": token, "token_type": "bearer"}

@app.post("/login", response_model=TokenResponse)
def login(user: User):
    email = user.email
    password = user.password

    if email not in cache:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    hashed_password = get_password_hash(password)
    stored_user = cache[email]

    if hashed_password != stored_user["password"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Generate a random token (you can replace this with JWT generation)
    token = stored_user["token"]

    return {"access_token": token, "token_type": "bearer"}


@app.post("/addPost", response_model=dict)
def add_post(post_data: PostSchema, current_user: User = Depends(authenticate_user)):
    if len(post_data.text) > 1024:
        raise HTTPException(status_code=400, detail="Post text is too long")

    post_id = str(uuid.uuid4())

    # Save the post in memory
    if current_user.email not in post_cache:
        post_cache[current_user.email] = []
    post_cache[current_user.email].append({"post_id": post_id, "text": post_data.text})

    return {"postID": post_id}

@app.get("/getPosts", response_model=list)
def get_posts(current_user: User = Depends(authenticate_user)):
    if current_user.email in response_cache:
        cached_posts = response_cache[current_user.email]
        return cached_posts

    if current_user.email not in post_cache:
        return []

    posts = post_cache[current_user.email]

    # Cache the posts for 5 minutes
    response_cache[current_user.email] = posts
    return posts

@app.delete("/deletePost", response_model=dict)
def delete_post(post_id: str , current_user: User = Depends(authenticate_user)):
    if current_user.email not in post_cache:
        raise HTTPException(status_code=400, detail="User has no posts")

    user_posts = post_cache[current_user.email]
    deleted = False
    for post in user_posts:
        if post["post_id"] == post_id:
            user_posts.remove(post)
            deleted = True
            break

    if deleted:
        return {"message": "Post deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Post not found")