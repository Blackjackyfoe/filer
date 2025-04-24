import io
import mimetypes
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path

import httpx
from fastapi import Cookie, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.logger import logger
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.security import HTTPBasic
from fastapi.templating import Jinja2Templates

# Configuration
UPLOAD_FOLDER = Path("files")
DEFAULT_FILES_LOCATION = "default/files"
BASE_URL = f"https://{os.environ.get('DOMAIN', 'localhost:8001')}"
ALLOWED_EXTENSIONS = {"txt", "png", "jpg", "jpeg", "gif", "ico", "docx", "webp", "heic", "heif", "tiff", "bmp"}
SUBURL = "/files"
ENV_MODE = "demo"
CHUNK_SIZE = 8192
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
FILE_SIGNATURES = {
    # PDF
    # b"%PDF": [".pdf"],
    # PNG
    b"\x89PNG\r\n\x1a\n": [".png"],
    # JPEG
    b"\xFF\xD8\xFF": [".jpg", ".jpeg"],
    # GIF
    b"GIF87a": [".gif"],
    b"GIF89a": [".gif"],
    # ICO
    b"\x00\x00\x01\x00": [".ico"],
    # DOCX (ZIP format)
    b"PK\x03\x04": [".docx"],
    # WEBP
    b"RIFF": [".webp"],  # Note: Need to check additional bytes
    # HEIC/HEIF (HEIC files start with HEIC or HEIX in ftyp box)
    b"\x00\x00\x00\x18ftyp": [".heic", ".heif"],
    # TIFF
    b"II*\x00": [".tiff"],  # Little-endian
    b"MM\x00*": [".tiff"],  # Big-endian
    # BMP
    b"BM": [".bmp"],
}
ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    # "application/pdf",
    "image/gif",
    "image/x-icon",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "image/webp",
    "image/heic",
    "image/heif",
    "image/tiff",
    "image/bmp",
}
MIME_TYPES = {
    # ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".tiff": "image/tiff",
    ".bmp": "image/bmp",
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """
    Startup function to make sure default files exists on their places
    """
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    for item in os.listdir(DEFAULT_FILES_LOCATION):
        source = os.path.join(DEFAULT_FILES_LOCATION, item)
        destination = os.path.join(UPLOAD_FOLDER, item)
        if os.path.isfile(source):
            shutil.copy2(source, destination)
        elif os.path.isdir(source):
            shutil.copytree(source, destination, dirs_exist_ok=True)

    logger.info(
        "Files copied from DEFAULT_FILES_LOCATION=%s to UPLOAD_FOLDER=%s", DEFAULT_FILES_LOCATION, UPLOAD_FOLDER
    )
    yield


app = FastAPI(lifespan=lifespan)


if ENV_MODE == "demo":
    origins = [BASE_URL, "http://localhost:3000"]
else:
    origins = [BASE_URL]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()
templates = Jinja2Templates(directory="templates")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def format_size(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0


def iframe_middleware(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        if "X-Frame-Options" not in request.headers:
            raise HTTPException(status_code=403, detail="Access denied")
        return await func(request, *args, **kwargs)

    return wrapper


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    # Check if the request is coming through a reverse proxy
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    if forwarded_proto:
        request.scope["scheme"] = forwarded_proto

    forwarded_host = request.headers.get("X-Forwarded-Host")
    if forwarded_host:
        request.scope["headers"].append((b"host", forwarded_host.encode()))

    response = await call_next(request)
    return response


async def verify_credentials(admin_authorization: str = Cookie(None)):
    if True:
        return "admin"

    if not admin_authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization is missing",
        )

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://server:8000/long-random-string/logined",
            cookies={"AdminAuthorization": admin_authorization},
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired credentials",
        )

    user_data = response.json()
    if user_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="You don't have access to this resource",
        )

    return user_data.get("role")


def get_file_info(path):
    stat = os.stat(path)
    size = stat.st_size
    modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")

    if os.path.isdir(path):
        return {
            "name": os.path.basename(path),
            "is_dir": True,
            "type": "Folder",
            "size": "-",
            "modified": modified,
        }
    else:
        file_type, _ = mimetypes.guess_type(path)
        if file_type is None:
            file_type = "application/octet-stream"

        return {
            "name": os.path.basename(path),
            "is_dir": False,
            "type": file_type,
            "size": format_size(size),
            "modified": modified,
        }


@app.post("/api/files/restore_backup")
async def restore_backup(
    backup_file: UploadFile = File(...),
    override: bool = Form(False),
):
    try:
        # Create a temporary directory to extract the zip
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = os.path.join(temp_dir_name, backup_file.filename)

            # Save the uploaded file
            with open(zip_path, "wb") as buffer:
                shutil.copyfileobj(backup_file.file, buffer)

            # Extract the zip file
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                for file in zip_ref.namelist():
                    target_path = os.path.join(UPLOAD_FOLDER, file)
                    if os.path.exists(target_path) and not override:
                        logger.info(f"Skipping existing file: {file}")
                        continue
                    zip_ref.extract(file, UPLOAD_FOLDER)
                    logger.info(f"Extracted: {file}")

        # Redirect to the main page after successful restore
        return RedirectResponse(url="/api/files", status_code=303)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error restoring backup: {str(e)}")


@app.get("/api/files/backup")
async def create_backup(request: Request):
    logger.info(f"Attempting to create backup from: {UPLOAD_FOLDER}")
    await verify_credentials(request.cookies.get("AdminAuthorization", None))
    if not os.path.exists(UPLOAD_FOLDER):
        logger.info(f"Upload folder not found: {UPLOAD_FOLDER}")
        raise HTTPException(status_code=404, detail=f"Upload folder not found: {UPLOAD_FOLDER}")

    try:
        files_to_backup = []
        for root, _, files in os.walk(UPLOAD_FOLDER):
            for file in files:
                file_path = os.path.join(root, file)
                files_to_backup.append(file_path)

        logger.info(f"Found {len(files_to_backup)} files to backup")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in files_to_backup:
                try:
                    arcname = os.path.relpath(file_path, UPLOAD_FOLDER)
                    zf.write(file_path, arcname)
                    logger.info(f"Added {file_path} to backup")
                except Exception as e:
                    logger.info(f"Error adding {file_path} to backup: {str(e)}")

        memory_file.seek(0)
        return StreamingResponse(
            iter([memory_file.getvalue()]),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=backup.zip"},
        )
    except Exception as e:
        logger.info(f"Error creating backup: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating backup: {str(e)}")


@app.get("/api/files/check_upload_folder")
async def check_upload_folder(request: Request):
    await verify_credentials(request.cookies.get("AdminAuthorization", None))
    try:
        if os.path.exists(UPLOAD_FOLDER):
            return {"status": "OK", "message": f"UPLOAD_FOLDER exists: {UPLOAD_FOLDER}"}
        return {
            "status": "Error",
            "message": f"UPLOAD_FOLDER does not exist: {UPLOAD_FOLDER}",
        }
    except Exception as e:
        return {"status": "Error", "message": f"Error checking UPLOAD_FOLDER: {str(e)}"}


@app.post("/api/files/upload")
async def upload_files(request: Request, subpath: str = Form(...), files: list[UploadFile] = File(...)):
    await verify_credentials(request.cookies.get("AdminAuthorization", None))
    if not is_safe_path(UPLOAD_FOLDER, Path(subpath)):
        raise HTTPException(status_code=400, detail="Invalid path")

    for file in files:
        new_filename = sanitize_filename(file.filename)
        if new_filename != file.filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        if not new_filename:
            raise HTTPException(status_code=400, detail="Missing filename")
        file_size = 0
        for chunk in iter(lambda: file.file.read(CHUNK_SIZE), b""):
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=400, detail="File too large")
        file.file.seek(0)

        file_extension = os.path.splitext(new_filename)[-1]
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=500, detail="Invalid request")
        if not verify_file_type(file):
            raise HTTPException(status_code=400, detail="File type doesn't match extension")

        file_path = os.path.join(UPLOAD_FOLDER, subpath, new_filename)
        try:
            with open(file_path, "xb") as buffer:  # 'x' flag ensures file doesn't exist
                shutil.copyfileobj(file.file, buffer)
        except FileExistsError:
            raise HTTPException(status_code=409, detail="File already exists")

    return JSONResponse(content={"success": True})


def is_safe_path(base_path: Path, path: Path) -> bool:
    """Check if the path is safe (doesn't escape base directory)"""
    try:
        return base_path.resolve() in path.resolve().parents
    except (ValueError, RuntimeError):
        return False


def sanitize_filename(filename: str) -> str:
    """Remove potentially dangerous characters from filename"""
    return re.sub(r"[^a-zA-Z0-9\s._-]", "", filename)


def verify_file_type(file: UploadFile) -> bool:
    """
    Verify file type using both file signatures and content analysis
    """
    # Read first 32 bytes (enough for most signatures)
    header = file.file.read(32)
    file.file.seek(0)  # Reset file pointer

    file_extension = Path(file.filename).suffix.lower()

    # Special case for WEBP (needs additional checking)
    if file_extension == ".webp" and header.startswith(b"RIFF"):
        # WEBP files have 'WEBP' at position 8
        return header[8:12] == b"WEBP"
    if file_extension == ".svg":
        try:
            # Read the entire file content
            content = file.file.read()
            file.file.seek(0)  # Reset file pointer

            # Check if content starts with XML declaration or SVG tag
            content_start = content[:100].lower()  # Check first 100 bytes
            is_xml = b"<?xml" in content_start
            has_svg_tag = b"<svg" in content_start

            # Basic validation: must have either XML declaration or SVG tag
            return is_xml or has_svg_tag
        except Exception:
            return False

    # Special case for HEIC/HEIF (needs to check for specific ftyp)
    if file_extension in [".heic", ".heif"] and b"ftyp" in header:
        # Check for HEIC/HEIF specific brands
        heic_brands = [b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs"]
        # Brand type starts 4 bytes after 'ftyp'
        ftyp_pos = header.find(b"ftyp")
        if ftyp_pos != -1 and ftyp_pos + 8 <= len(header):
            brand = header[ftyp_pos + 8 : ftyp_pos + 12].lower()
            return any(brand.startswith(b) for b in heic_brands)
        return False

    # Check against known signatures
    for signature, extensions in FILE_SIGNATURES.items():
        if header.startswith(signature):
            return file_extension in extensions

    return False


@app.post("/api/files/upload_verification")
async def upload_files_hash(bidHash: str = Form(...), files: list[UploadFile] = File(...)):
    try:
        pass
    except Exception:
        return JSONResponse(status_code=400, content={"success": False})
    try:
        bid_folder = UPLOAD_FOLDER / "bids" / bidHash
        if not is_safe_path(UPLOAD_FOLDER, Path(bid_folder)):
            raise HTTPException(status_code=400, detail="Invalid path")

        result = []
        for file in files:
            if not file.filename:
                raise HTTPException(status_code=400, detail="Missing filename")
            file_size = 0
            for chunk in iter(lambda: file.file.read(CHUNK_SIZE), b""):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=400, detail="File too large")
            file.file.seek(0)

            if not verify_file_type(file):
                raise HTTPException(
                    status_code=400,
                    # detail="File type doesn't match extension"
                )
            file_uuid = str(uuid.uuid4())
            file_extension = os.path.splitext(file.filename)[-1]
            new_filename = sanitize_filename(f"{file_uuid}{file_extension}")
            file_path = bid_folder / new_filename

            bid_folder.mkdir(parents=True, exist_ok=True)
            if file_path.exists():
                raise HTTPException(status_code=409, detail="File already exists")

            try:
                with open(file_path, "xb") as buffer:  # 'x' flag ensures file doesn't exist
                    shutil.copyfileobj(file.file, buffer)
            except FileExistsError:
                raise HTTPException(
                    status_code=409,
                    # detail="File already exists"
                )

            file_uri = f"{BASE_URL}/files/bids/{bidHash}/{new_filename}"
            result.append({"id": file_uuid, "url": file_uri, "name": new_filename})

        return JSONResponse(content={"success": True, "files": result})
    except Exception as e:
        return JSONResponse(content={"success": False})


@app.get("/files", response_class=FileResponse)
@app.get("/files/{subpath:path}", response_class=FileResponse)
# @iframe_middleware # TODO: make norm wrapper for verify credentials
async def get_image(
    request: Request,
    subpath: str = "",
):
    full_path = os.path.join(UPLOAD_FOLDER, subpath)

    if os.path.isfile(full_path):
        return FileResponse(full_path)
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/api/files", response_class=HTMLResponse)
@app.get("/api/files/{subpath:path}", response_class=HTMLResponse)
# @iframe_middleware # TODO: make norm wrapper for verify credentials
async def index(
    request: Request,
    subpath: str = "",
):
    full_path = os.path.join(UPLOAD_FOLDER, subpath)

    if os.path.isfile(full_path):
        return FileResponse(full_path)

    if full_path.endswith("/"):
        await verify_credentials(request.cookies.get("AdminAuthorization", None))

    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Path not found")

    if os.path.isdir(full_path):
        items = set(os.listdir(full_path))
        if "system" in items:
            items.remove("system")

        files = [get_file_info(os.path.join(full_path, item)) for item in items]

        # Sort directories first, then files, both alphabetically
        files.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))

        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "files": files,
                "subpath": subpath,
                "full_path": full_path,
                "env_mode": os.getenv("ENV_MODE", None),
            },
        )

    raise HTTPException(status_code=400, detail="Not a file or directory")


@app.post("/api/files/upload/{subpath:path}")
async def upload_file(
    subpath: str,
    request: Request,
    file: UploadFile = File(...),
):
    await verify_credentials(request.cookies.get("AdminAuthorization", None))

    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")
    new_filename = sanitize_filename(file.filename)
    if new_filename != file.filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not new_filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    file_size = 0
    for chunk in iter(lambda: file.file.read(CHUNK_SIZE), b""):
        file_size += len(chunk)
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
    file.file.seek(0)

    if not verify_file_type(file):
        raise HTTPException(status_code=400, detail="File type doesn't match extension")

    file_path = os.path.join(UPLOAD_FOLDER, subpath, new_filename)
    try:
        with open(file_path, "xb") as buffer:  # 'x' flag ensures file doesn't exist
            shutil.copyfileobj(file.file, buffer)
    except FileExistsError:
        raise HTTPException(status_code=409, detail="File already exists")

    return {"filename": file.filename, "status": "File uploaded successfully"}


@app.post("/api/files/create_folder")
async def create_folder(
    request: Request,
    subpath: str = Form(default=""),
    folder_name: str = Form(...),
):
    await verify_credentials(request.cookies.get("AdminAuthorization", None))
    folder_name_sanitized = sanitize_filename(folder_name)
    if folder_name_sanitized != folder_name:
        raise HTTPException(status_code=400, detail="Invalid path")
    new_dir = os.path.join(UPLOAD_FOLDER, subpath, folder_name_sanitized)
    if not is_safe_path(UPLOAD_FOLDER, Path(new_dir)) or "/" in folder_name:
        raise HTTPException(status_code=400, detail="Invalid path")
    try:
        os.makedirs(new_dir, exist_ok=True)
        return JSONResponse(content={"success": True})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/files/delete/{subpath:path}")
async def delete_item(request: Request, subpath: str):
    await verify_credentials(request.cookies.get("AdminAuthorization", None))
    full_path = os.path.join(UPLOAD_FOLDER, subpath)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Path not found")

    if os.path.isfile(full_path):
        os.remove(full_path)
    elif os.path.isdir(full_path):
        shutil.rmtree(full_path)
    else:
        raise HTTPException(status_code=400, detail="Not a file or directory")

    parent_path = os.path.dirname(subpath)
    return RedirectResponse(url=f"/api/files/{parent_path}", status_code=303)


@app.post("/api/files/rename/{subpath:path}")
async def rename_item(
    subpath: str,
    request: Request,
    new_name: str = Form(...),
):
    await verify_credentials(request.cookies.get("AdminAuthorization", None))
    full_path = os.path.join(UPLOAD_FOLDER, subpath)
    parent_path = os.path.dirname(subpath)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Path not found")

    directory, old_name = os.path.split(full_path)

    if old_name == new_name:
        return RedirectResponse(url=f"/api/files/{parent_path}", status_code=303)

    new_path = os.path.join(directory, new_name)

    if os.path.exists(new_path):
        raise HTTPException(status_code=400, detail="A file or directory with this name already exists")

    os.rename(full_path, new_path)

    return RedirectResponse(url=f"/api/files/{parent_path}", status_code=303)
