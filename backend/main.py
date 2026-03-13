from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import shutil
import asyncio
import uuid

from osint_tools import (
    phone_lookup, ip_lookup, mac_lookup,
    generate_search_links, breach_lookup,
    extract_metadata, stress_test
)

app = FastAPI(title="OmniIntel OSINT API")

# Allow frontend (if served separately)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend (assuming frontend files are in ../frontend)
# For production, you might serve frontend separately.
# Here we'll serve index.html as root.
@app.get("/")
async def serve_frontend():
    return FileResponse("../frontend/index.html")

@app.get("/api/phone/{number}")
async def phone(number: str):
    result = phone_lookup(number)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.get("/api/ip/{query}")
async def ip(query: str):
    result = ip_lookup(query)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.get("/api/mac/{mac}")
async def mac(mac: str):
    result = mac_lookup(mac)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.post("/api/image-search")
async def image_search(data: dict):
    url = data.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing image URL")
    links = generate_search_links(url)
    return links

@app.get("/api/breach/{query}")
async def breach(query: str):
    result = breach_lookup(query)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.post("/api/metadata")
async def metadata(file: UploadFile = File(...)):
    # Save temporarily
    file_ext = os.path.splitext(file.filename)[1]
    temp_filename = f"/tmp/{uuid.uuid4()}{file_ext}"
    with open(temp_filename, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    result = extract_metadata(temp_filename)
    os.remove(temp_filename)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.websocket("/ws/stress")
async def websocket_stress(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        target = data.get("target")
        duration = data.get("duration", 5)
        if not target:
            await websocket.send_json({"error": "Missing target"})
            await websocket.close()
            return

        # Run stress test and send updates
        for update in stress_test(target, duration):
            await websocket.send_json({"progress": update})
            await asyncio.sleep(0.1)  # small delay to avoid flooding
        await websocket.close()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"error": str(e)})

        await websocket.close()
