#!/usr/bin/env bash
set -e

ROOT_DIR="EduCore"
mkdir -p "$ROOT_DIR"
echo "Creating project in ./$ROOT_DIR ..."

# README.md
cat > "$ROOT_DIR/README.md" <<'EOF'
# EduCore — Starter (MVP) repo

Bu repository EduCore loyihasi uchun minimal ishchi skeleton: FastAPI backend (SQLite) va React frontend (Vite).

Asosiy xususiyatlar:
- Ro'yxatdan o'tish / login (JWT)
- Kurslar ro'yxati va kurs yaratish (teacher)
- To'lov endpoint — muvaffaqiyatsiz holatlarda Telegram fallback xabari ko'rsatiladi
- Minimal React frontend: kurslar ko'rsatadi va to'lov sahifasida Telegram kontaktini chiqaradi

Requirments:
- Docker & docker-compose (recommended) yoki Python 3.10+ va Node.js 18+

Ishga tushirish (Docker):
1. docker-compose up --build
2. Backend: http://localhost:8000
3. Frontend: http://localhost:3000

Agar GitHub ga push qilishni xohlasangiz, menga repozitoriya nomi va egasini bering yoki ruxsat bering men GitHub Actions orqali push qilaman.

To'lov fallback xabari:
"To'lov qilish payti kelganda yoki to'lov amalga oshmay qolsa, telegramdan @Azizbek_1990_year ga yozing."

Replit dizayn inspiratsiyasi: https://replit.com/join/wmrxenxbtx-techtrenduz
EOF

# .gitignore
cat > "$ROOT_DIR/.gitignore" <<'EOF'
venv/
__pycache__/
node_modules/
dist/
.env
*.db
*.sqlite3
EOF

# docker-compose.yml
cat > "$ROOT_DIR/docker-compose.yml" <<'EOF'
version: "3.8"
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app
    environment:
      - SECRET_KEY=supersecretchangeit
      - DATABASE_URL=sqlite:///./educore.db
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app
    environment:
      - VITE_API_BASE=http://host.docker.internal:8000
EOF

# backend
mkdir -p "$ROOT_DIR/backend/app"
cat > "$ROOT_DIR/backend/Dockerfile" <<'EOF'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
EOF

cat > "$ROOT_DIR/backend/requirements.txt" <<'EOF'
fastapi
uvicorn[standard]
sqlmodel
passlib[bcrypt]
python-jose[cryptography]
python-multipart
EOF

cat > "$ROOT_DIR/backend/app/main.py" <<'EOF'
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import SQLModel, Field, create_engine, Session, select
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
from jose import JWTError, jwt
import os

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretchangeit")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

sqlite_url = os.getenv("DATABASE_URL", "sqlite:///./educore.db")
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

app = FastAPI(title="EduCore MVP")

# Models
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str
    name: Optional[str] = None
    hashed_password: str
    role: str = "student"  # student/teacher/admin

class Course(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    description: Optional[str] = ""
    price: float = 0.0
    author_id: Optional[int] = None
    is_premium: bool = False

# Schemas
class UserCreate(BaseModel):
    email: str
    password: str
    name: Optional[str] = None
    role: Optional[str] = "student"

class Token(BaseModel):
    access_token: str
    token_type: str

class CourseCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    price: float = 0.0
    is_premium: bool = False

class CourseRead(BaseModel):
    id: int
    title: str
    description: Optional[str]
    price: float
    is_premium: bool

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

# Auth helpers
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(session: Session, email: str, password: str):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise credentials_exception
    return user

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Routes
@app.post("/auth/register", response_model=Token)
def register(data: UserCreate, session: Session = Depends(get_session)):
    existing = session.exec(select(User).where(User.email == data.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=data.email, name=data.name, hashed_password=get_password_hash(data.password), role=data.role)
    session.add(user)
    session.commit()
    session.refresh(user)
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"email": current_user.email, "name": current_user.name, "role": current_user.role}

@app.post("/courses", response_model=CourseRead)
def create_course(payload: CourseCreate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if current_user.role not in ("teacher", "admin"):
        raise HTTPException(status_code=403, detail="Only teachers/admins can create courses")
    course = Course(title=payload.title, description=payload.description, price=payload.price, is_premium=payload.is_premium, author_id=current_user.id)
    session.add(course)
    session.commit()
    session.refresh(course)
    return course

@app.get("/courses", response_model=List[CourseRead])
def list_courses(session: Session = Depends(get_session)):
    courses = session.exec(select(Course)).all()
    return courses

# Payment create endpoint (simulated)
@app.post("/payments/create")
def create_payment(course_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    course = session.exec(select(Course).where(Course.id == course_id)).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    # Simulate a payment attempt and failure (in real app integrate provider)
    # When payment fails, provide Telegram fallback instruction
    return {
        "status": "failed",
        "message": "To'lov amalga oshmadi. Iltimos, quyidagi Telegram orqali murojaat qiling: @Azizbek_1990_year"
    }
EOF

# frontend
mkdir -p "$ROOT_DIR/frontend/src"
cat > "$ROOT_DIR/frontend/Dockerfile" <<'EOF'
FROM node:18
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host"]
EOF

cat > "$ROOT_DIR/frontend/package.json" <<'EOF'
{
  "name": "educore-frontend",
  "version": "0.0.1",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.4.0"
  },
  "devDependencies": {
    "vite": "^5.0.0",
    "@vitejs/plugin-react": "^4.0.0"
  }
}
EOF

cat > "$ROOT_DIR/frontend/index.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>EduCore MVP</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
EOF

cat > "$ROOT_DIR/frontend/src/main.jsx" <<'EOF'
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

createRoot(document.getElementById("root")).render(<App />);
EOF

cat > "$ROOT_DIR/frontend/src/App.jsx" <<'EOF'
import React, { useEffect, useState } from "react";
import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

function App() {
  const [courses, setCourses] = useState([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetchCourses();
  }, []);

  async function fetchCourses() {
    try {
      const res = await axios.get(`${API_BASE}/courses`);
      setCourses(res.data);
    } catch (e) {
      console.error(e);
    }
  }

  async function register() {
    try {
      const res = await axios.post(`${API_BASE}/auth/register`, { email, password, name: "User" });
      setToken(res.data.access_token);
      localStorage.setItem("token", res.data.access_token);
      setMessage("Ro'yxatdan o'tdingiz");
    } catch (e) {
      setMessage("Xatolik: " + (e.response?.data?.detail || e.message));
    }
  }

  async function buyCourse(id) {
    try {
      const res = await axios.post(`${API_BASE}/payments/create?course_id=${id}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.data.status === "failed") {
        alert(res.data.message + "\n\nDizayn: https://replit.com/join/wmrxenxbtx-techtrenduz");
      } else {
        alert("Sotib olish muvaffaqiyatli");
      }
    } catch (e) {
      alert("Payment error. Telegram: @Azizbek_1990_year");
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: "Arial, sans-serif" }}>
      <h1>EduCore — MVP</h1>

      <section style={{ marginBottom: 20 }}>
        <h2>Ro'yxatdan o'tish</h2>
        <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
        <input placeholder="Parol" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button onClick={register}>Ro'yxatdan o'tish</button>
        <div>{message}</div>
      </section>

      <section>
        <h2>Kurslar</h2>
        <ul>
          {courses.map(c => (
            <li key={c.id} style={{ marginBottom: 8 }}>
              <strong>{c.title}</strong> — {c.description} {c.is_premium ? `(Premium ${c.price}$)` : `(Bepul)`}
              <div>
                <button onClick={() => buyCourse(c.id)} style={{ marginTop: 6 }}>
                  Kursni sotib olish / kirish
                </button>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <footer style={{ marginTop: 40, color: "#666" }}>
        To'lov muammosi bo'lsa: <strong>@Azizbek_1990_year</strong><br />
        Dizayn inspiratsiyasi: <a href="https://replit.com/join/wmrxenxbtx-techtrenduz" target="_blank">Replit dizayn</a>
      </footer>
    </div>
  );
}

export default App;
EOF

# Create zip
ZIP_NAME="EduCore.zip"
echo "Creating zip archive $ZIP_NAME ..."
cd "$ROOT_DIR/.." || exit 1
if command -v zip >/dev/null 2>&1; then
  zip -r "$ZIP_NAME" "$ROOT_DIR" >/dev/null
else
  # fallback using python
  python3 - <<PY
import shutil
shutil.make_archive("EduCore", "zip", "$ROOT_DIR")
PY
  # move created archive to current dir
  if [ -f "EduCore.zip" ]; then
    echo "Archive created."
  fi
fi

echo "Done. Archive is: ./EduCore.zip"
echo "You can now upload or download EduCore.zip. To inspect: unzip -l EduCore.zip"